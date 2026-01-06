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