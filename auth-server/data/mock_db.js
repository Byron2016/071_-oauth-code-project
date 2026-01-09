/**
 * MOCK DATABASE LAYER
 * Centraliza el almacenamiento en memoria y las consultas de datos.
 */

// Almacenes en memoria (Maps)
const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();

/**
 * Inicializa los clientes permitidos basándose en la configuración del .env
 * @param {Object} config - Objeto de configuración cargado desde env.js
 */
/*
Explicación del motivo por el que no es necesario importar nuevamente el config.
1. El patrón de "Inyección de Dependencias"
En el diseño que propusimos, el archivo mock_db.js no "busca" la configuración, sino que la recibe como un regalo.

Fíjate en la función que definimos:

JavaScript

// En mock_db.js
export function initializeClients(config) { // <--- Recibe el objeto 'config' aquí
  clients.set(config.clientId, { ... });   // <--- Aquí ya lo puede usar
}
Cuando ejecutas esta función en tu index_auth_server.js, haces esto:

JavaScript

// En index_auth_server.js
import { config } from "./config/env.js"; // El import se hace AQUÍ
import { initializeClients } from "./data/mock_db.js";

initializeClients(config); // Le pasas el objeto completo al mock
Conclusión: El mock_db.js no necesita importar el archivo de configuración porque el index_auth_server.js (que sí tiene el import) le entrega todos los datos necesarios a través de los argumentos de la función.

2. Evitar la "Dependencia Circular"
Esta es la razón de arquitectura. Si el mock_db.js importara el config, y luego el config (o el servidor principal) necesitara algo del mock, podrías crear un bucle de importaciones que Node.js a veces no maneja bien.

Al hacerlo mediante una función de inicialización:

Mantenemos el Mock limpio: El archivo de datos no sabe nada de archivos .env ni de lógica de servidor.

Flexibilidad: Si mañana quieres probar el servidor con un clientId distinto para un test, puedes llamar a initializeClients({ clientId: 'test-client' }) sin tener que cambiar el archivo .env real.

¿Qué pasa con los otros archivos?
index_auth_server.js: Sigue siendo el "jefe" que orquesta todo. Él tiene el import { config } y distribuye las piezas a los demás módulos.

crypto_utils.js: Tampoco tiene imports de configuración, porque solo recibe strings o buffers para procesar, lo cual lo hace una "función pura".

En resumen: config.clientId está disponible porque se lo pasas como parámetro en la función de arranque, no porque el archivo lo conozca de antemano.
*/
function initializeClients(config) {
  // Limpiamos por si se llama más de una vez
  clients.clear();

  clients.set(config.clientId, {
    client_id: config.clientId,
    // El .split(",") permite manejar múltiples URIs si se desea en el futuro y Ya es un array, no necesita []
    redirectUris: config.redirectUri.split(","),
  });

  console.log(`✅ Cliente [${config.clientId}] inicializado correctamente.`);
}

/**
 * Simulación de base de datos de usuarios
 * En una app real, aquí harías: return db.users.find({ email })
 */
function getDemoUser() {
  return {
    sub: "alice",
    name: "Alice Example",
    email: "alice@example.com",
  };
}

export {
  clients,
  authorizationCodes,
  refreshTokens,
  initializeClients,
  getDemoUser,
};
