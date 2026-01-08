// 1. Importaciones y Configuración Inicial
import express from "express"; // Importa el framework web para crear el servidor.
import cookieParser from "cookie-parser"; // Middleware para leer y manipular cookies del navegador.
import axios from "axios"; // Librería para realizar peticiones HTTP a otros servidores.
import { randomBytes, createHash } from "crypto"; // Funciones nativas de Node para seguridad y criptografía.

const app = express();
app.use(cookieParser()); // Habilita el soporte de cookies en la aplicación.

const AUTH_SERVER = "http://localhost:3000"; // URL del servidor de identidad (donde el usuario se loguea).
const RESOURCE_SERVER = "http://localhost:5000"; // URL de la API que tiene los datos protegidos.

const CLIENT_ID = "demo-client"; // Identificador de esta aplicación registrado en el servidor de auth.
const REDIRECT_URI = "http://localhost:4000/callback"; // URL a la que el servidor de auth enviará el código.

// Helpers
// 2. Funciones de Ayuda (PKCE y Seguridad)
// Estas funciones preparan el terreno para el flujo PKCE, que evita que un atacante intercepte el código de autorización.

// Convierte un buffer en una cadena Base64 segura para URLs (sin +, / o =).
function base64url(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// Genera el "code_verifier": un secreto aleatorio y único para esta sesión de login.
function generateVerifier() {
  return base64url(randomBytes(32));
}

// Crea el "code_challenge": un hash SHA256 del verifier. Se envía al servidor al inicio.
function codeChallengeS256(verifier) {
  const hash = createHash("sha256").update(verifier).digest();
  return base64url(hash);
}

// Genera un valor aleatorio "state" para prevenir ataques CSRF (falsificación de peticiones).
function generateState() {
  return base64url(randomBytes(16));
}

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

  const { access_token, refresh_token } = tokenRes.data;

  // Guarda los tokens obtenidos en cookies para mantener la sesión del usuario.
  res.cookie("access_token", access_token, { httpOnly: true });
  res.cookie("refresh_token", refresh_token, { httpOnly: true });

  // Limpia las cookies temporales de OAuth que ya no son necesarias.
  res.clearCookie("code_verifier");
  res.clearCookie("oauth_state");

  res.redirect("/profile"); // Va a la página de perfil.
});

app.get("/profile", async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.redirect("/");

  try {
    const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    res.send(`<pre>${JSON.stringify(apiRes.data, null, 2)}</pre>`);
  } catch (err) {
    const msg = err?.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;
    res.status(500).send(`API call failed: ${msg}`);
  }
});

// 5. Uso de Tokens y Refresco
// Ruta protegida que consume datos del Resource Server.
app.get("/profile", async (req, res) => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) return res.redirect("/"); // Si no hay token, no está logueado.

  try {
    // Llama a la API externa enviando el Access Token en el header Authorization.
    const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    res.send(`<pre>${JSON.stringify(apiRes.data, null, 2)}</pre>`);
  } catch (err) {
    const msg = err?.response?.data ? JSON.stringify(err.response.data) : err.message;
    res.status(500).send(`API call failed: ${msg}`);
  }
});

// Ruta para renovar el Access Token cuando este caduca.
app.get("/refresh", async (req, res) => {
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
app.listen(4000, () => {
  console.log("Client App running on http://localhost:4000");
});

app.listen(4000, () => {
  console.log("Client App running on http://localhost:4000");
});
