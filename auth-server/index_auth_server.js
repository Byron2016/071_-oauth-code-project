// Este código corresponde a un Servidor de Authorización
import { config } from "./config/env.js";
import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { SignJWT, exportJWK, importPKCS8, importSPKI } from "jose";

import { sha256Base64url, generateCode } from "./utils/crypto_utils.js";
import {
  clients,
  authorizationCodes,
  refreshTokens,
  initializeClients, // Mirar en el mock la importancia de esto.
  getDemoUser,
} from "./data/mock_db.js";

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

// Inicialización de datos
initializeClients(config);

const PRIVATE_KEY_PEM = config.keys.private;
const PUBLIC_KEY_PEM = config.keys.public;

const ISSUER = config.issuer;
const KEY_ID = config.key_id;

app.get("/authorize", (req, res) => {
  console.log(`Entró al auth-server /authorize`);
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
  const user = getDemoUser(); // Ahora viene de mock_db

  const code = generateCode();

  const AUTH_CODE_TTL = parseInt(config.auth_code_expires_ms);

  // authorizationCodes está disponible por la importación del mock_db
  authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    scope,
    user,
    expiresAt: Date.now() + AUTH_CODE_TTL, // x miliseconds
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
  console.log(`Entró al auth-server /token`);
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
      .setExpirationTime(config.access_token_duration)
      .sign(privateKey);

    // Primero conviertes los días del .env a milisegundos
    const REFRESH_TTL_MS =
      parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || 30) *
      24 *
      60 *
      60 *
      1000;

    const refresh_token = generateCode();
    refreshTokens.set(refresh_token, {
      sub: record.user.sub,
      scope: record.scope,
      clientId: client_id,
      expiresAt: Date.now() + REFRESH_TTL_MS,
    });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.access_token_expires_in_sec,
      refresh_token,
      scope: record.scope,
    });
  }

  if (grant_type === "refresh_token") {
    console.log(`Entró al auth-server /token refresh_token`);
    const { refresh_token, client_id } = req.body;
    const record = refreshTokens.get(refresh_token);
    if (!record) return res.status(400).json({ error: "invalid_grant" });
    if (record.clientId !== client_id)
      return res.status(400).json({ error: "invalid_grant" });

    const privateKey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    console.log(
      `Entró al auth-server /token refresh_token antes const accessToken = await...`
    );
    const accessToken = await new SignJWT({ scope: record.scope })
      .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
      .setIssuer(ISSUER)
      .setAudience(client_id)
      .setSubject(record.sub)
      .setIssuedAt()
      .setExpirationTime(config.access_token_duration) //15m
      .sign(privateKey);

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.access_token_expires_in_sec,
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

/**
 * JWKS endpoint:
 * Resource servers fetch public keys here to validate JWT signatures.
 */
app.get("/.well-known/jwks.json", async (req, res) => {
  console.log(`Entró al auth-server /.well-known/jwks.json`);
  //const privateKey = await importSPKI(PRIVATE_KEY_PEM, "RS256");

  // jose export JWK from a key object, but we need public JWK
  // For tutorial simplicity, jose can export from private key too (it includes public parts)
  //const jwk = await exportJWK(privateKey); //25.24
  const publicKey = await importSPKI(PUBLIC_KEY_PEM, "RS256");
  const jwk = await exportJWK(publicKey);

  jwk.use = "sig";
  jwk.alg = "RS256";
  jwk.kid = KEY_ID;

  res.status(200).json({
    keys: [jwk],
  });
});

app.listen(config.port, () => {
  console.log(`🚀 Auth Server running on ${config.issuer}`);
});
