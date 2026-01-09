import fs from "node:fs";

// 1. Cargar el archivo .env
process.loadEnvFile();

// 2. Definir qué variables son obligatorias
const REQUIRED_VARS = [
  "PORT",
  "KEY_ID",
  "ISSUER_HOST",
  "CLIENT_ID",
  "REDIRECT_URI_ALLOWED",
  "PRIVATE_KEY_PATH",
  "PUBLIC_KEY_PATH",
  "AUTH_CODE_EXPIRES_MS",
  "ACCESS_TOKEN_DURATION",
  "ACCESS_TOKEN_EXPIRES_IN_SEC",
  "REFRESH_TOKEN_EXPIRES_DAYS",
];

// 3. Validar presencia de variables
const missing = REQUIRED_VARS.filter((v) => !process.env[v]);
if (missing.length > 0) {
  console.error(`❌ Faltan variables en el .env: ${missing.join(", ")}`);
  process.exit(1);
}

// 4. Validar existencia física de las llaves PEM
[process.env.PRIVATE_KEY_PATH, process.env.PUBLIC_KEY_PATH].forEach((path) => {
  if (!fs.existsSync(path)) {
    console.error(`❌ Archivo de llave no encontrado: ${path}`);
    process.exit(1);
  }
});

const getKeys = () => {
  try {
    return {
      private: fs.readFileSync(process.env.PRIVATE_KEY_PATH, "utf8"),
      public: fs.readFileSync(process.env.PUBLIC_KEY_PATH, "utf8"),
    };
  } catch (error) {
    console.error(`❌ Error leyendo archivos de llaves: ${error.message}`);
    process.exit(1);
  }
};

// 5. Extraer y Construir Configuración Final
const config = {
  port: process.env.PORT,
  key_id: process.env.KEY_ID,
  issuer: `${process.env.ISSUER_HOST}:${process.env.PORT}`,
  clientId: process.env.CLIENT_ID,
  redirectUri: process.env.REDIRECT_URI_ALLOWED,
  auth_code_expires_ms: process.env.AUTH_CODE_EXPIRES_MS,
  access_token_duration: process.env.ACCESS_TOKEN_DURATION,
  access_token_expires_in_sec: process.env.ACCESS_TOKEN_EXPIRES_IN_SEC,
  refresh_token_expires_days: process.env.REFRESH_TOKEN_EXPIRES_DAYS,
  // Leemos las llaves de una vez
  keys: getKeys(),
};

// 6. Configurar el Cliente por medio del config exportado
export { config };
