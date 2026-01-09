import { randomBytes, createHash } from "node:crypto"; // Funciones nativas de Node para seguridad y criptografía.

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

export { generateVerifier, codeChallengeS256, generateState };
