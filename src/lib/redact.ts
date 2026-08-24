/**
 * Value-level secret scrubbing.
 *
 * The specification forbids the DigitalOcean token from reaching logs. Path-based
 * redaction only covers keys we remembered to name, so this also scrubs by *value*:
 * a token embedded in an error message from a dependency we do not control still gets
 * caught. Everything that can reach a log or a persisted `error` column goes through
 * `scrub()` first.
 */

const SECRET_PATTERNS: ReadonlyArray<RegExp> = [
  /\bdop_v1_[A-Za-z0-9_-]+/g, // personal access token -- the credential this app uses
  /\bdoo_v1_[A-Za-z0-9_-]+/g, // OAuth access token
  /\bdor_v1_[A-Za-z0-9_-]+/g, // OAuth refresh token
  /\bdos_v1_[A-Za-z0-9_-]+/g, // Spaces-adjacent token
  /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, // Authorization header values
  /\b[a-z]+:\/\/[^:@\s/]+:[^@\s/]+@/gi, // credentials embedded in a connection URI
];

/** Keys whose entire value is replaced, whatever shape it has. */
const SECRET_KEYS: ReadonlySet<string> = new Set(
  [
    "authorization",
    "token",
    "access_token",
    "accesstoken",
    "refresh_token",
    "refreshtoken",
    "secret",
    "client_secret",
    "password",
    "private_key",
    "privatekey",
    "certificate",
    "ca_certificate",
    "kubeconfig",
    "credentials",
    "connection_string",
    "cookie",
    "set-cookie",
    "digitalocean_token",
  ].map((k) => k.toLowerCase()),
);

export const REDACTED = "[REDACTED]";

export function scrubString(input: string): string {
  let out = input;
  for (const pattern of SECRET_PATTERNS) out = out.replace(pattern, REDACTED);
  return out;
}

/** Deep-scrub an arbitrary value. Cycle-safe; Errors and Buffers are normalised. */
export function scrub(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === "string") return scrubString(value);
  if (value === null || typeof value !== "object") return value;

  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (value instanceof Error) {
    return { name: value.name, message: scrubString(value.message) };
  }
  if (Array.isArray(value)) return value.map((v) => scrub(v, seen));

  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    out[key] = SECRET_KEYS.has(key.toLowerCase()) ? REDACTED : scrub(val, seen);
  }
  return out;
}

/**
 * Turn any thrown value into a message safe to persist in `sync_runs.error` or show
 * in the UI. Truncated, because upstream bodies can be large and are not useful past
 * the first line or two.
 */
export function sanitizeError(error: unknown, maxLength = 500): string {
  const raw =
    error instanceof Error ? error.message : typeof error === "string" ? error : String(error);
  const scrubbed = scrubString(raw);
  return scrubbed.length > maxLength ? `${scrubbed.slice(0, maxLength)}...` : scrubbed;
}

/**
 * A non-reversible fingerprint for display: enough for a human to tell two tokens
 * apart, useless to anyone who reads it. Never shows a prefix, only the tail.
 */
export function tokenFingerprint(token: string | undefined): string | null {
  if (!token || token.length < 8) return null;
  return `****${token.slice(-4)}`;
}
