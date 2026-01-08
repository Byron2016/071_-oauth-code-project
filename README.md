<div>
	<div>
		<img src=https://raw.githubusercontent.com/Byron2016/00_forImages/main/images/Logo_01_00.png align=left alt=MyLogo width=200>
	</div>
	&nbsp;
	<div>
		<h1>071_-oauth-code-project</h1>
	</div>
</div>

&nbsp;

## Project Description 

**071_-oauth-code-project** is a practice to understan the use of **OAuth 2.0 Course for Beginners**  following freeCodeCamp's tuto: 
**rt_001_tuto**: [freeCodeCamp.org: OAuth 2.0 Course for Beginners](https://www.youtube.com/watch?v=WSsOXo07LeE) and the other help that you can find into **Reference** section.
&nbsp;

## Technologies used

![HTML](https://img.shields.io/static/v1?label=&message=HTML&color=red&logo=html&logoColor=white&style=for-the-badge)
![JAVASCRIPT](https://img.shields.io/static/v1?label=&message=javascript&color=yellow&logo=javascript3&logoColor=white&style=for-the-badge)

## References

- freeCodeCamp.org

  - [freeCodeCamp.org: OAuth 2.0 Course for Beginners](https://www.youtube.com/watch?v=WSsOXo07LeE)


## Steps

- **Initial concepts**
  - **OAuth 2.0** is an industry-standard authorization framework that lets users grant third-party applications limited access to their data (like photos or contacts) on another service (like Google or Facebook) without sharing their actual passwords, using temporary access tokens for secure delegate access across web, mobile and desktop apps.

    - 1. OAuth 2.0: La "Llave Electrónica" (Autorización)
        OAuth is mainly for authorization, what an app can do and authentication like who are you is usually handled via OpenId connect on top of OAuth.

        OAuth no le dice al hotel quién eres tú; simplemente le dice al sistema qué puertas tienes permiso para abrir.

        ¿Qué hace? Gestiona permisos.

        El ejemplo del hotel: Cuando haces el check-in, te dan una tarjeta magnética. Esa tarjeta no tiene tu nombre ni tu cara, pero tiene un chip que dice: "Esta tarjeta puede abrir la habitación 302 y el gimnasio, pero no la oficina del gerente".

        En la web: Cuando una app te pide "permiso para ver tus contactos de Google", Google te da un Access Token (la tarjeta). La app usa ese token para entrar a tus contactos, pero la app no sabe necesariamente "quién" eres tú a nivel de perfil, solo sabe que tiene permiso para leer esa lista.

    - 2. OpenID Connect (OIDC): El "DNI" (Autenticación)
        Como OAuth solo sirve para dar permisos, se inventó OpenID Connect para añadir la parte de la identidad. Es una capa que se construye encima de OAuth.

        ¿Qué hace? Confirma quién eres.

        El ejemplo del hotel: Es el momento en que el recepcionista mira tu pasaporte y comprueba que tú eres realmente la persona de la reserva.

        En la web: OIDC añade un nuevo elemento llamado ID Token. Este token es como un carnet de identidad digital que contiene tu nombre, tu email y tu foto de perfil. 


  - **OAuth rules you'll reference** 
    - **Resource owner** which is the user
    - **Client** the app that trying to access the data
    - **The authorization server** is the server that logs the user in and issues tokens off server 
    - **The resource server** the API holding protected data rosorce server.
  
  - **What a PKCE is**
    - Proof Key for Code Exchange. Es una extensión de seguridad para el protocolo OAuth 2.0 diseñada específicamente para hacer que el inicio de sesión en aplicaciones sea mucho más seguro
    - **¿Cómo funciona PKCE? (La solución)**
        PKCE soluciona esto introduciendo un "secreto dinámico" que se crea en el momento. Imagina que es como un apretón de manos secreto que cambia en cada inicio de sesión:

        **1.- El Secreto (Code Verifier):** Tu app genera una frase aleatoria y secreta (ej: secreto_super_largo_123).

        **2.- El Desafío (Code Challenge):** La app transforma ese secreto (usualmente usando una función matemática llamada SHA-256) y envía esa versión "transformada" al servidor de Google/Facebook.

        **3.- El Bloqueo:** El servidor guarda ese desafío.

        **4.- La Verificación:** Cuando la app recibe el código de vuelta, tiene que enviar el secreto original (secreto_super_largo_123). El servidor hace la cuenta matemática y dice: "Ah, el secreto coincide con el desafío que me enviaste antes. Eres tú de verdad".
    - **Explicación**
  
      - **Paso 1: Generar el "Secreto" (Code Verifier)**
        Todo empieza en tu aplicación (en tu móvil o navegador). La app inventa una clave secreta aleatoria y única para ese momento.

        **Qué es:** Una cadena de texto aleatoria de entre 43 y 128 caracteres.

        **Seguridad:** Este secreto nunca sale de tu dispositivo en este paso. Se queda guardado en la memoria de la app.

        **Ejemplo:** mi_clave_secreta_super_larga_123_abc.

      - **Paso 2: Crear el "Desafío" (Code Challenge)**
        La app no puede enviar el secreto tal cual, porque si alguien lo intercepta, se acabó la seguridad. Así que lo transforma matemáticamente.

        **La Transformación:** Se aplica un algoritmo llamado SHA-256 al secreto. Es una función "unidireccional": puedes convertir el secreto en el desafío, pero es imposible volver atrás.

        **El envío:** La app envía este Code Challenge al servidor de Google/Facebook junto con tu petición de inicio de sesión.

        **El servidor anota:** El servidor guarda ese desafío y dice: "Vale, cuando este usuario vuelva, me tendrá que demostrar que conoce el secreto original que genera este código".

      - **Paso 3: El "Bloqueo" (Intercambio del Código)**
        Una vez que te logueas con tu usuario y contraseña, el servidor te devuelve un Código de Autorización.

        **El riesgo:** Aquí es donde el hacker podría intentar robar ese código.

        **La defensa:** Aunque el hacker robe el código, no tiene el secreto del Paso 1. El servidor ha "bloqueado" el proceso: el código por sí solo no sirve para entrar, necesita la pieza que falta.

      - **Paso 4: La Verificación Final**
        Tu app recibe el código y ahora tiene que dar el paso final para obtener el "Token" (la llave real para entrar).

        **Envío del secreto:** La app envía al servidor el código que recibió MÁS el secreto original (el Code Verifier del paso 1).

        **La comprobación:** El servidor coge ese secreto, le aplica el algoritmo SHA-256 y mira el resultado.

        **El "Match":** Si el resultado coincide con el Code Challenge que le enviaste en el Paso 2, el servidor sabe que tú eres el mismo que inició la petición.

        **Éxito:** El servidor te entrega el Access Token y ya puedes usar la app.

        **Aquí te explico por qué ese envío final es seguro y por qué no rompe la protección del sistema:**
          **1. El canal de comunicación es distinto**
            En el **Paso 2**, la comunicación suele ser a través de un "redireccionamiento" en el navegador (una URL que salta de un sitio a otro). Ese canal es más vulnerable porque el historial del navegador o los registros del sistema pueden "ver" la URL.
            Sin embargo, en el **Paso 4** (donde se envía el secreto), la app hace una petición **POST directa** de servidor a servidor (o de app a servidor) usando **HTTPS (TLS)**.
                - Los datos viajan dentro de un túnel encriptado.
                - Nadie en el camino (ni tu vecino en el Wi-Fi, ni el proveedor de internet) puede ver el contenido.
          
          **2. El "Código de Autorización" ya no es útil para nadie más**
            Para cuando el secreto sale en el Paso 4, el Código de Autorización (el que podría haber sido interceptado) ya está siendo canjeado.
                - Los servidores de OAuth están configurados para que ese código funcione una sola vez.
                - Si un hacker intentara usar ese código un segundo después, el servidor lo rechazaría.
                
          **3. El factor "Unión Vinculante"**
            Lo más importante es que el servidor solo aceptará el secreto si "encaja" con el desafío que enviaste en el Paso 2.
                - El atacante no pudo haber enviado el desafío correcto al principio (porque no conocía el secreto).
                - Por lo tanto, aunque el atacante vea el secreto al final (que es casi imposible por el HTTPS), ya no tiene un Código de Autorización válido que coincida con ese secreto.

          **4. ¿Por qué se envía el secreto al final?**
            Porque el servidor necesita la prueba. No puede saber si tú eres el dueño legítimo a menos que le muestres el secreto original para que él mismo haga la cuenta matemática ($SHA256(Secreto) = Desafío$).


- **Server**
  - Crear carpeta *auth-server* <code>mkdir auth-server</code>
  - Crear package.json <code>pnpm init</code>
  - Agregar al package.json el type: <code>"type": "module"</code>
  - Agregar paquetes 
    ```bash
        pnpm add express cookie-parser body-parser jose
    ```
  - Agregar index.js
  - Generar private key
    ```bash
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
        openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in private.pem -out private_pkcs8.pem
    ```

  - Actualizar index.js
    ```js
      import express from "express";
      import bodyParser from "body-parser";
      import cookieParser from "cookie-parser";
      import { randomBytes, createHash } from "node:crypto";
      import { SignJWT, exportJWK, importPKCS8, importSPKI } from "jose";
      import fs from "node:fs";

      const app = express();
      app.use(bodyParser.urlencoded({ extended: false }));
      app.use(bodyParser.json());
      app.use(cookieParser());

      const clients = new Map();
      const authorizationCodes = new Map();
      const refreshTokens = new Map();

      clients.set("demo-client", {
        client_id: "demo-client",
        redirectUris: ["http://localhost:4000/callback"],
      });

      const PRIVATE_KEY_PEM = fs.readFileSync("./private.pem", "utf8");
      //const PUBLIC_KEY_PEM = fs.readFileSync("./public.pem", "utf8");

      const ISSUER = "http://localhost:3000";
      const KEY_ID = "demo-key-1";

      function base64url(input) {
        return (
          input
            .toString("base64")
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            //.replace(/\//g, "=")
            .replace(/=+$/g, "")
        );
      }

      function sha256Base64url(str) {
        const hash = createHash("sha256").update(str).digest();
        return base64url(hash);
      }

      function generateCode() {
        return base64url(randomBytes(32));
      }

      function getDemoUser() {
        return { sub: "alice", name: "Alice Example", email: "alice@example.com" };
      }

      app.get("/authorize", (req, res) => {
        const {
          response_type,
          client_id,
          redirect_uri,
          scope = "",
          state,
          code_challenge,
          code_challenge_method,
        } = req.query;

        // Basic validation
        const client = clients.get(client_id);
        if (!client) return res.status(400).send("Unknown client_id");
        if (!client.redirectUris.includes(redirect_uri))
          return res.status(400).send("Invalid redirect_uri");
        if (response_type !== "code")
          return res.status(400).send("Only response_type=code supported");
        if (!code_challenge || code_challenge_method !== "S256") {
          return res
            .status(400)
            .send(
              "PKCE required: provide code_challenge and code_challenge_method=S256"
            );
        }

        // Normally: show login + consent UI.
        // For tutorial simplicity: auto-login + auto-consent.
        const user = getDemoUser();

        const code = generateCode();
        authorizationCodes.set(code, {
          clientId: client_id,
          redirectUri: redirect_uri,
          codeChallenge: code_challenge,
          scope,
          user,
          expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
        });

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
       */
      app.post("/token", async (req, res) => {
        const { grant_type } = req.body;

        if (grant_type === "authorization_code") {
          const { code, redirect_uri, client_id, code_verifier } = req.body;

          const record = authorizationCodes.get(code);
          if (!record)
            return res
              .status(400)
              .json({ error: "invalid_grant", error_description: "Unknown code" });
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
          const computedChallenge = sha256Base64url(code_verifier);
          if (computedChallenge !== record.codeChallenge) {
            return res.status(400).json({
              error: "invalid_grant",
              error_description: "PKCE validation failed",
            });
          }

          // One-time use code
          authorizationCodes.delete(code);

          // Create JWT access token
          const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

          const accessToken = await new SignJWT({
            scope: record.scope,
            name: record.user.name,
            email: record.user.email,
          })
            .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
            .setIssuer(ISSUER)
            .setAudience(client_id)
            .setSubject(record.user.sub)
            .setIssuedAt()
            .setExpirationTime("15m")
            .sign(privateKey);

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

        if (grant_type === "refresh_token") {
          const { refresh_token, client_id } = req.body;
          const record = refreshTokens.get(refresh_token);
          if (!record) return res.status(400).json({ error: "invalid_grant" });
          if (record.clientId !== client_id)
            return res.status(400).json({ error: "invalid_grant" });

          const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

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
      app.get("/.well-known/jwks.json", async (req, res) => {
        const privateKey = await importSPKI(PRIVATE_KEY_PEM, "RS256");

        // jose export JWK from a key object, but we need public JWK
        // For tutorial simplicity, jose can export from private key too (it includes public parts)
        const jwk = await exportJWK(privateKey); //25.24

        jwk.use = "sig";
        jwk.alg = "RS256";
        jwk.kid = KEY_ID;

        res.status(200).json({
          keys: [jwk],
        });
      });

      app.listen(3000, () => {
        console.log("Auth Server running on http://localhost:3000");
      });
    ```
- **Resource-Server**
  - What we can do with this one is that and now we'll have to have this server is the protecte API. It will like kind of read authorization bearer token. it will fetch the JWKS from author server. It will also verify token signature plus issuer plus audience plus expiry all of that kind of good stuff. Also allow requist only if token is valid. so We´ll have to install the dependencies.

  - Crear carpeta *resource-server* <code>mkdir resource-server</code>
  - Crear package.json <code>pnpm init</code>
  - Agregar al package.json el type: <code>"type": "module"</code>
  - Agregar paquetes 
    ```bash
        pnpm add express jose
    ```
  - Agregar index.js

  - Actualizar index.js
    ```js
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
          const { payLoad } = await jwtVerify(token, JWKS, {
            issuer: ISSUER,
            audience: AUDIENCE,
          });

          // Si todo es correcto, guarda la información del usuario (payload) dentro del objeto 'req'
          // para que las siguientes funciones puedan usarla.
          req.user = payLoad;
          next(); // Permite que la petición continúe al siguiente paso.
        } catch (err) {
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
          const scopes = String(req.user?.scope || "")
            .split(" ")
            .filter(Boolean);

          // Si el array de scopes del usuario no incluye el scope requerido por la ruta, deniega el acceso.
          if (!scopes.includes(scope)) {
            return res
              .status(403)
              .json({ error: "insufficient_scope", required: scope }); // 403 significa "Prohibido" (autenticado pero sin permiso).
          }
          next(); // El usuario tiene permiso, continúa a la ruta.
        };
      }

      /**
       * RUTA PROTEGIDA: /api/profile
       * Esta ruta requiere que el usuario esté autenticado Y tenga el permiso "api.read".
       */
      app.get("/api/profile", requireAuth, requireScope("api.read"), (req, res) => {
        // Si llegamos aquí, el token es válido y el permiso existe.
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
    ```