import fs from "node:fs";

// 1. Cargar el archivo .env
process.loadEnvFile();

// 2. Definir qué variables son obligatorias
const REQUIRED_VARS = [
  "PORT",
  "RESOURCE_HOST",
  "ISSUER_HOST",
  "AUDIENCE",
  "JWKS_URL",
];

// 3. Validar presencia de variables
const missing = REQUIRED_VARS.filter((v) => !process.env[v]);
if (missing.length > 0) {
  console.error(`❌ Faltan variables en el .env: ${missing.join(", ")}`);
  process.exit(1);
}

// 5. Extraer y Construir Configuración Final
const config = {
  port: process.env.PORT,
  resource_host: `${process.env.RESOURCE_HOST}:${process.env.PORT}`,
  issuer_host: process.env.ISSUER_HOST,
  audience: process.env.AUDIENCE,
  jwks_url: process.env.JWKS_URL,
};

// 6. Configurar el Cliente por medio del config exportado
export { config };
