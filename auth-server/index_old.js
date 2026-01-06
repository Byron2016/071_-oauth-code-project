import express from "express"; // Framework web para manejar rutas (GET, POST) y el servidor HTTP.
import bodyParser from "body-parser"; // Middleware para procesar el cuerpo de las peticiones (JSON o formularios).
import cookieParser from "cookie-parser"; // Permite leer y manipular cookies enviadas por el navegador.
import { randomBytes, createHash } from "crypto"; // Módulo nativo de Node.js para generar valores aleatorios y hashes (SHA256).
import { SignJWT, exportJWK, importPKCS8, importSPKI } from "jose"; // Librería especializada en JWT (JSON Web Tokens) y JWKS.
// importPKCS8 (Para la Llave Privada): Se usa en la ruta /token. PKCS#8 es el formato estándar para llaves privadas. Se usa para firmar los tokens (ponerles el "sello" de autenticidad).
// importSPKI (Para la Llave Pública): Se usa en la ruta /.well-known/jwks.json. SPKI es el formato estándar para llaves públicas. Se usa para que el servidor pueda "leer" su propia llave pública y luego entregarla a otros en formato JSON, para que ellos puedan verificar la firma.
import fs from "node:fs";

const app = express();
// CONFIGURACIÓN DE MIDDLEWARES
app.use(bodyParser.urlencoded({ extended: false })); // Permite recibir datos de formularios (application/x-www-form-urlencoded).
// extended: false: Utiliza la librería querystring de Node.js. Es más sencilla y no permite objetos anidados. Solo genera pares de clave-valor simples (strings o arrays).

// extended: true: Utiliza la librería qs. Es mucho más potente y permite crear objetos complejos y anidados desde el formulario.

app.use(bodyParser.json()); // Permite recibir datos en formato JSON.
app.use(cookieParser()); // Habilita el manejo de cookies en las peticiones.

// BASES DE DATOS EN MEMORIA (Simuladas con Maps)
const clients = new Map(); // Almacena los clientes permitidos (ej: tu App Frontend).
const authorizationCodes = new Map(); // Almacena códigos temporales tras el login exitoso.
const refreshTokens = new Map(); // Almacena tokens de larga duración para renovar sesiones.

// Registro de un cliente de prueba
clients.set("demo-client", {
  client_id: "demo-client",
  redirectUris: ["http://localhost:4000/callback"], // URL permitida para devolver el código.
});

// Momentáneamente quemada para fines educativos.
const PRIVATE_KEY_PEM = fs.readFileSync("./private.pem", "utf8");
// La llave pública se comparte para que otros VERIFIQUEN que el token es auténtico.
const PUBLIC_KEY_PEM = fs.readFileSync("./public.pem", "utf8");

const ISSUER = "http://localhost:3000";
const KEY_ID = "demo-key-1"; //demo-key-id

// FUNCIONES DE UTILIDAD
// Función para codificar en Base64url (sin padding '=')
// Convierte un buffer a formato Base64URL (estándar para URLs, sin caracteres especiales como + o /).
function base64url(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// Genera un hash SHA256 y lo convierte a Base64URL (para validar PKCE).
function sha256Base64url(str) {
  const hash = createHash("sha256").update(str).digest();
  return base64url(hash);
}

// Genera una cadena aleatoria segura para códigos y tokens.
function generateCode() {
  return base64url(randomBytes(32));
}

// Simulación de un usuario autenticado tras el login.
function getDemoUser() {
  return { sub: "alice", name: "Alice Example", email: "alice@example.com" };
}

/**
 * RUTA: /authorize
 * El cliente (App) redirige al usuario aquí para iniciar sesión.
 */
app.get("/authorize", (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope = "",
    state,
    code_challenge, // Parte de PKCE: reto enviado por el cliente.
    code_challenge_method,
  } = req.query;

  // Basic validation
  const client = clients.get(client_id);
  if (!client) return res.status(400).send("Unknown client_id");
  if (!client.redirectUris.includes(redirect_uri))
    return res.status(400).send("Invalid redirect_uri");
  if (response_type !== "code")
    return res.status(400).send("Only response_type=code supported");
  // PKCE es obligatorio en este flujo para evitar ataques de interceptación.
  if (!code_challenge || code_challenge_method !== "S256") {
    return res
      .status(400)
      .send(
        "PKCE required: provide code_challenge and code_challenge_method=S256"
      );
  }

  // Normally: show login + consent UI.
  // For tutorial simplicity: auto-login + auto-consent.
  // En un sistema real, aquí iría el formulario de Login y Consentimiento.
  const user = getDemoUser();

  // Generamos un código de autorización temporal.
  const code = generateCode();
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    scope,
    user,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
  });

  // Redirigimos de vuelta a la App con el código en la URL.
  const redirect = new URL(redirect_uri);
  redirect.searchParams.set("code", code);
  if (state) redirect.searchParams.set("state", state);

  res.redirect(redirect.toString());
});

/**
 * POST /token
 * Supports:
 * - grant_type=authorization_code
 * - grant_type=refresh_token
 * Intercambia el código de autorización por tokens reales (Access y Refresh).
 */
app.post("/token", async (req, res) => {
  const { grant_type } = req.body;

  // FLUJO 1: Intercambio de código (authorization_code)
  if (grant_type === "authorization_code") {
    const { code, redirect_uri, client_id, code_verifier } = req.body;

    const record = authorizationCodes.get(code);
    if (!record)
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Unknown code" });
    // Verificación de expiración
    if (record.expiresAt < Date.now()) {
      authorizationCodes.delete(code);
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Code expired" });
    }
    if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Client mismatch" });
    }

    // PKCE validation
    // Validación de seguridad de PKCE
    // El cliente envía el 'code_verifier'. Si su hash coincide con el 'code_challenge' guardado, es legítimo.
    const computedChallenge = sha256Base64url(code_verifier);
    if (computedChallenge !== record.codeChallenge) {
      return res.status(400).json({
        error: "invalid_grant",
        error_description: "PKCE validation failed",
      });
    }

    // One-time use code
    // El código se borra tras un solo uso (Seguridad).
    authorizationCodes.delete(code);

    // Create JWT access token
    // CREACIÓN DEL ACCESS TOKEN (JWT)
    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    const accessToken = await new SignJWT({
      scope: record.scope,
      name: record.user.name,
      email: record.user.email,
    })
      .setProtectedHeader({ alg: "RS256", kid: KEY_ID }) // Header con algoritmo y ID de llave.
      .setIssuer(ISSUER)
      .setAudience(client_id)
      .setSubject(record.user.sub)
      .setIssuedAt()
      .setExpirationTime("15m") // El token de acceso dura poco (15 min).
      .sign(privateKey); // Firma digitalmente.

    // Generamos un Refresh Token (opcional, para obtener nuevos Access Tokens después).
    const refresh_token = generateCode();
    refreshTokens.set(refresh_token, {
      sub: record.user.sub,
      scope: record.scope,
      clientId: client_id,
    });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 900,
      refresh_token,
      scope: record.scope,
    });
  }

  // FLUJO 2: Renovación de token (refresh_token)
  if (grant_type === "refresh_token") {
    const { refresh_token, client_id } = req.body;
    const record = refreshTokens.get(refresh_token);
    if (!record) return res.status(400).json({ error: "invalid_grant" });
    if (record.clientId !== client_id)
      return res.status(400).json({ error: "invalid_grant" });

    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    // Genera un nuevo Access Token sin pedir login al usuario.
    const accessToken = await new SignJWT({ scope: record.scope })
      .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
      .setIssuer(ISSUER)
      .setAudience(client_id)
      .setSubject(record.sub)
      .setIssuedAt()
      .setExpirationTime("15m")
      .sign(privateKey);

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 900,
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

/**
 * JWKS endpoint:
 * Resource servers fetch public keys here to validate JWT signatures.
 */
/**
 * RUTA: JWKS (JSON Web Key Set)
 * Expone la LLAVE PÚBLICA para que cualquier Microservicio o API pueda
 * verificar que los tokens enviados fueron firmados por este servidor.
 */
app.get("/.well-known/jwks.json", async (req, res) => {
  const publicKey = await importSPKI(PUBLIC_KEY_PEM, "RS256");
  const jwk = await exportJWK(publicKey); // Convierte el .pem a formato JSON (JWK).

  jwk.use = "sig"; // Uso: Firma (Signature).
  jwk.alg = "RS256";
  jwk.kid = KEY_ID;

  res.status(200).json({
    keys: [jwk],
  });
});

app.listen(3000, () => {
  console.log("Auth Server running on http://localhost:3000");
});
