import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Encryption for the stored OAuth token.
 *
 * An OAuth token has to be persisted — unlike the personal access token, it arrives at
 * runtime and cannot live in the environment. So it is encrypted with AES-256-GCM
 * under a key supplied through the environment, which is what the specification asks
 * for when an app saves connections.
 *
 * ponytail: encrypts directly under the master key rather than wrapping a per-row data
 * key. The envelope scheme in DigitalOceanIntegration/backend earns its extra layer by
 * enabling KMS drop-in and per-row rotation across many tenants; here there is one row
 * and one tenant. Move to that scheme if this ever stores more than one connection.
 */

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export class MissingMasterKeyError extends Error {
  constructor() {
    super(
      "TOKEN_MASTER_KEY is not set, so an OAuth token cannot be stored safely. " +
        "Generate one with: openssl rand -base64 32",
    );
    this.name = "MissingMasterKeyError";
  }
}

function masterKey(): Buffer {
  const raw = process.env.TOKEN_MASTER_KEY?.trim();
  if (!raw) throw new MissingMasterKeyError();

  const key = Buffer.from(raw, "base64");
  if (key.byteLength !== 32) {
    throw new Error(
      `TOKEN_MASTER_KEY must decode to exactly 32 bytes (got ${key.byteLength}). ` +
        "Generate one with: openssl rand -base64 32",
    );
  }
  return key;
}

export function hasMasterKey(): boolean {
  try {
    masterKey();
    return true;
  } catch {
    return false;
  }
}

/**
 * `aad` binds the ciphertext to what it is. Without it, a stored access token could be
 * swapped into the refresh-token column and would still decrypt.
 */
export function encrypt(plaintext: string, aad: string): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", masterKey(), nonce);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const body = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  // nonce ‖ ciphertext ‖ tag, base64 — one self-describing column value.
  return Buffer.concat([nonce, body, cipher.getAuthTag()]).toString("base64");
}

export function decrypt(stored: string, aad: string): string {
  const raw = Buffer.from(stored, "base64");
  if (raw.byteLength <= NONCE_BYTES + TAG_BYTES) {
    throw new Error("Stored token is malformed.");
  }

  const nonce = raw.subarray(0, NONCE_BYTES);
  const body = raw.subarray(NONCE_BYTES, raw.byteLength - TAG_BYTES);
  const tag = raw.subarray(raw.byteLength - TAG_BYTES);

  const decipher = createDecipheriv("aes-256-gcm", masterKey(), nonce);
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
}
