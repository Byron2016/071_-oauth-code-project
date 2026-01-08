// Este código corresponde a un Servidor de Recursos (API). Su función es proteger datos privados y solo entregarlos si el cliente presenta un Access Token (JWT) válido, emitido por el servidor de autorización que analizamos anteriormente.

// IMPORTACIONES
import express from "express"; // Framework para crear el servidor y definir las rutas de la API.

// jwtVerify: para validar la firma del token.
// createRemoteJWKSet: para obtener la llave pública automáticamente desde el servidor de identidad.
import { jwtVerify, createRemoteJWKSet } from "jose";

const app = express();
app.use(express.json()); // Middleware para que la API pueda entender cuerpos de peticiones en formato JSON.

// CONFIGURACIÓN DE SEGURIDAD
const ISSUER = "http://localhost:3000"; // La URL del servidor que emitió el token (debe coincidir exactamente).
const AUDIENCE = "demo-client"; // El ID del cliente para el que fue emitido el token (evita que un token de la App A se use en la App B).
const JWKS_URL = new URL("http://localhost:3000/.well-known/jwks.json"); // Dirección donde el servidor de recursos baja la llave pública para verificar tokens.

// Crea un conjunto de llaves remotas. Esto permite que el servidor valide el JWT sin tener la llave guardada localmente;
// la descarga de la URL y la mantiene en caché.
const JWKS = createRemoteJWKSet(JWKS_URL);

/**
 * MIDDLEWARE: requireAuth
 * Se encarga de interceptar la petición y verificar si el usuario está autenticado.
 */
async function requireAuth(req, res, next) {
  console.log(">>>>Ejecutando middleware de resource-server requireAuth");
  const auth = req.headers.authorization; // Busca el encabezado "Authorization".
  // Verifica si el encabezado existe y si usa el esquema "Bearer ".
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" }); // Si no hay token, detiene la petición con error 401 (No autorizado).
  }

  const token = auth.slice("Bearer ".length); // Extrae solo la cadena del token (quita la palabra "Bearer ").

  try {
    // VALIDA EL TOKEN:
    // 1. Verifica la firma con las llaves del JWKS.
    // 2. Revisa que no haya expirado.
    // 3. Comprueba que el ISSUER y AUDIENCE sean correctos.
    console.log(`-->resource-server requireAuth`);
    //console.log(`token: ${token} `);
    console.log(`jwks: ${JWKS} `);
    console.log(`issuer: ${ISSUER} `);
    console.log(`audience: ${AUDIENCE}`);
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });
    console.log("-->Luego de  const { payLoad }");
    console.log(payload);
    // Si todo es correcto, guarda la información del usuario (payload) dentro del objeto 'req'
    // para que las siguientes funciones puedan usarla.
    req.user = payload;
    console.log(req.user);
    console.log("--> resource-server requireAuth antes next()");
    next(); // Permite que la petición continúe al siguiente paso.
  } catch (err) {
    console.log(
      "Ejecutando middleware de resource-server requireAuth en el catch con error"
    );
    console.log(`error: ${err}`);
    // Si el token es falso, expiró o está mal formado, devuelve un error.
    return res
      .status(401)
      .json({ error: "invalid_token", message: err.message });
  }
}

/**
 * MIDDLEWARE: requireScope
 * Verifica si el usuario tiene permiso (permisos específicos llamados 'scopes') para hacer una acción.
 */

function requireScope(scope) {
  return (req, res, next) => {
    // Convierte el string de scopes del token (ej: "api.read profile") en un array para buscar fácilmente.
    console.log(">>>>Ejecutando middleware de resource-server requireScope");
    const scopes = String(req.user?.scope || "")
      .split(" ")
      .filter(Boolean);
    console.log(`scopes: ${scopes}`);

    // Si el array de scopes del usuario no incluye el scope requerido por la ruta, deniega el acceso.
    if (!scopes.includes(scope)) {
      return res
        .status(403)
        .json({ error: "insufficient_scope", required: scope }); // 403 significa "Prohibido" (autenticado pero sin permiso).
    }
    console.log("--> resource-server requireScope antes next()");
    next(); // El usuario tiene permiso, continúa a la ruta.
  };
}

/**
 * RUTA PROTEGIDA: /api/profile
 * Esta ruta requiere que el usuario esté autenticado Y tenga el permiso "api.read".
 */
app.get("/api/profile", requireAuth, requireScope("api.read"), (req, res) => {
  // Si llegamos aquí, el token es válido y el permiso existe.
  console.log(
    "1.- Ejecutando /api/profile luego de los middlewares requireAuth, requireScope"
  );
  res.json({
    message: "Protected profile data",
    user: {
      sub: req.user.sub, // ID único del usuario.
      name: req.user.name, // Nombre del usuario (extraído del JWT).
      email: req.user.email, // Email del usuario (extraído del JWT).
      scope: req.user.scope, // Scopes que tiene permitidos.
    },
  });
});

// El servidor de recursos corre en un puerto distinto (5000) para no chocar con el de autorización (3000).
app.listen(5000, () => {
  console.log("Resource Server running on http://localhost:5000");
});
