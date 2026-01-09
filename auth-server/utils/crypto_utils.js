import { randomBytes, createHash } from "node:crypto";

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

export { sha256Base64url, generateCode };
