import fs from "node:fs";

// 1. Cargar el archivo .env
process.loadEnvFile();

// 2. Definir qué variables son obligatorias
const REQUIRED_VARS = [
  "PORT",
  "CLIENT_HOST",
  "AUTH_SERVER_URL",
  "RESOURCE_SERVER_URL",
  "CLIENT_ID",
  "REDIRECT_URI",
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
  client_host: `${process.env.CLIENT_HOST}:${process.env.PORT}`,
  auth_server_url: process.env.AUTH_SERVER_URL,
  resoruce_server_url: process.env.RESOURCE_SERVER_URL,
  clientId: process.env.CLIENT_ID,
  redirectUri: process.env.REDIRECT_URI,
};

// 6. Configurar el Cliente por medio del config exportado
export { config };
