// Este código corresponde a un client-app.
// 1. Importaciones y Configuración Inicial
import { config } from "./config.js";
import express from "express"; // Importa el framework web para crear el servidor.
import cookieParser from "cookie-parser"; // Middleware para leer y manipular cookies del navegador.
import axios from "axios"; // Librería para realizar peticiones HTTP a otros servidores.

import {
  generateVerifier,
  codeChallengeS256,
  generateState,
} from "./utils/crypto_utils.js";

const app = express();
app.use(cookieParser()); // Habilita el soporte de cookies en la aplicación.

const AUTH_SERVER = config.auth_server_url; // URL del servidor de identidad (donde el usuario se loguea).
const RESOURCE_SERVER = config.resoruce_server_url; // URL de la API que tiene los datos protegidos.

const CLIENT_ID = config.clientId; // Identificador de esta aplicación registrado en el servidor de auth.
const REDIRECT_URI = config.redirectUri; // URL a la que el servidor de auth enviará el código.

// 3. Ruta de Inicio y Login
// Ruta principal: muestra un simple enlace para iniciar sesión.
app.get("/", (req, res) => {
  res.send(`
    <h2>Client App</h2>
    <p>This app uses Authorization Code + PKCE.</p>
    <a href="/login">Login</a>
  `);
});

// Inicia el proceso de autenticación.
app.get("/login", (req, res) => {
  const code_verifier = generateVerifier(); // Crea el secreto.
  const code_challenge = codeChallengeS256(code_verifier); // Crea el desafío derivado del secreto.
  const state = generateState(); // Crea el token de seguridad para la sesión.

  // Guarda el verifier y el state en cookies cifradas (httpOnly) para usarlos después del redirect.
  res.cookie("code_verifier", code_verifier, { httpOnly: true });
  res.cookie("oauth_state", state, { httpOnly: true });

  // Construye la URL de redirección hacia el Servidor de Autorización.
  const authorizeUrl = new URL(`${AUTH_SERVER}/authorize`);
  authorizeUrl.searchParams.set("response_type", "code"); // Indica que queremos un código de autorización.
  authorizeUrl.searchParams.set("client_id", CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeUrl.searchParams.set("scope", "api.read openid profile email"); // Permisos solicitados.
  authorizeUrl.searchParams.set("state", state); // Para validar que la respuesta vuelva a nosotros.
  authorizeUrl.searchParams.set("code_challenge", code_challenge); // Envía el desafío PKCE.
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authorizeUrl.toString()); // Envía al usuario a la página de login del servidor central.
});

// 4. El Callback (Intercambio de Código por Token)
app.get("/callback", async (req, res) => {
  const { code, state } = req.query; // Recupera el código y el estado que el servidor envió por URL.

  if (!code) return res.status(400).send("Missing authorization code");

  // SEGURIDAD: Verifica que el "state" recibido sea igual al que guardamos en la cookie original.
  if (state !== req.cookies.oauth_state) {
    return res.status(400).send("Invalid state");
  }

  const code_verifier = req.cookies.code_verifier; // Recupera el secreto original guardado antes.

  // Petición POST al servidor de identidad para cambiar el código por tokens reales.
  const tokenRes = await axios.post(
    `${AUTH_SERVER}/token`,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier, // Aquí enviamos el secreto PKCE para demostrar que somos el mismo que inició el login.
    }).toString(),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );

  const { access_token, refresh_token, expires_in } = tokenRes.data;

  // Guarda los tokens obtenidos en cookies para mantener la sesión del usuario.
  res.cookie("access_token", access_token, { httpOnly: true });
  res.cookie("refresh_token", refresh_token, { httpOnly: true });

  // Limpia las cookies temporales de OAuth que ya no son necesarias.
  res.clearCookie("code_verifier");
  res.clearCookie("oauth_state");

  res.send(`
    <h3>Logged in!</h3>
    <p>Access token expires in ${expires_in} seconds.</p>
    <a href="/profile">Call Protected API</a>
    <br /><br />
    <a href="/refresh">Refresh Access Token</a>
  `);

  //res.redirect("/profile"); // Va a la página de perfil.
});

// new5. Uso de Tokens y Refresco
// Ruta protegida que consume datos del Resource Server.
app.get("/profile", async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.redirect("/"); // Si no hay token, no está logueado.

  try {
    // Llama a la API externa enviando el Access Token en el header Authorization.
    console.log(`Inicio profile.. ${RESOURCE_SERVER}/api/profile`);
    const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    res.send(`<pre>${JSON.stringify(apiRes.data, null, 2)}</pre>`);
  } catch (err) {
    console.log("Ejecutando en client-app /profile en el primer catch ");
    //console.log(err);
    const msg = err?.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    res.status(500).send(`API call failed: ${msg}`);
  }
});

// Ruta para renovar el Access Token cuando este caduca.
app.get("/refresh", async (req, res) => {
  console.log(`Entro al index_client_app app.get("/refresh"`);
  const refreshToken = req.cookies.refresh_token;
  if (!refreshToken) return res.redirect("/");

  // Envía el Refresh Token al servidor de auth para obtener un nuevo Access Token.
  const tokenRes = await axios.post(
    `${AUTH_SERVER}/token`,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    }).toString(),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
  );

  // Actualiza la cookie con el nuevo token de acceso.
  res.cookie("access_token", tokenRes.data.access_token, { httpOnly: true });

  res.send(`
    <h3>Refreshed Access Token!</h3>
    <a href="/profile">Call Protected API Again</a>
  `);
});

// Inicia el servidor en el puerto 4000.
app.listen(config.port, () => {
  console.log(`🚀 Resource Server running on ${config.client_host}`);
});
