import "server-only";
import { dataSource, environmentToken } from "../lib/env";
import { oauthAccessToken } from "../oauth/digitalocean";

/**
 * Which credential to call DigitalOcean with.
 *
 * Server-only, and marked as such: it reads the database, so importing it from a
 * client component would pull SQLite into the browser bundle. The `server-only`
 * package turns that mistake into a build error instead of a confusing runtime one.
 *
 * An OAuth connection wins when one exists. It is the more explicit act, and a stale
 * environment token silently overriding a connection the user just made through the
 * UI would be baffling.
 */
export function digitalOceanCredential(): string | undefined {
  return oauthAccessToken() ?? environmentToken();
}

export type CredentialSource = "fixtures" | "oauth" | "environment" | "none";

export function credentialSource(): CredentialSource {
  // Sample-data mode calls no API, so there is no credential to have. Reporting "none"
  // would gate the whole app behind a connection it does not need, which is exactly
  // the token-free path an evaluator without a DigitalOcean account has to take.
  if (dataSource() === "fixtures") return "fixtures";
  if (oauthAccessToken()) return "oauth";
  return environmentToken() ? "environment" : "none";
}
