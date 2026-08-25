/**
 * Environment access.
 *
 * The DigitalOcean token is read here and nowhere else, always at call time. It is
 * never cached in a module-level variable that could end up in a heap dump, never
 * written to the database, and never returned to the browser.
 */

export type DataSource = "live" | "fixtures";

export function dataSource(): DataSource {
  return process.env.DATA_SOURCE === "fixtures" ? "fixtures" : "live";
}

/**
 * The token from the environment, if set.
 *
 * Deliberately knows nothing about the database: this module is imported by client
 * components, so anything it touches ends up in the browser bundle. The "which
 * credential should we actually use" question lives in src/do/credential.ts, which is
 * server-only.
 *
 * Callers must not log or persist the return value.
 */
export function environmentToken(): string | undefined {
  const token = process.env.DIGITALOCEAN_TOKEN?.trim();
  return token && token.length > 0 ? token : undefined;
}

/** Back-compat alias for call sites that only care about the environment. */
export const digitalOceanToken = environmentToken;

export function apiBaseUrl(): string {
  return process.env.DIGITALOCEAN_API_BASE ?? "https://api.digitalocean.com";
}
