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

/** The raw token, or undefined. Callers must not log or persist the return value. */
export function digitalOceanToken(): string | undefined {
  const token = process.env.DIGITALOCEAN_TOKEN?.trim();
  return token && token.length > 0 ? token : undefined;
}

export class MissingTokenError extends Error {
  constructor() {
    super(
      "DIGITALOCEAN_TOKEN is not set. Add a read-only (api:read) personal access token " +
        "to .env, or run with DATA_SOURCE=fixtures to evaluate the app without one.",
    );
    this.name = "MissingTokenError";
  }
}

export function requireDigitalOceanToken(): string {
  const token = digitalOceanToken();
  if (!token) throw new MissingTokenError();
  return token;
}

export function apiBaseUrl(): string {
  return process.env.DIGITALOCEAN_API_BASE ?? "https://api.digitalocean.com";
}
