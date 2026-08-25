import { createHash, randomBytes } from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { getDb } from "../db/client";
import { oauthConnection, oauthStates } from "../db/schema";
import { decrypt, encrypt } from "./crypto";

/**
 * DigitalOcean's authorization code flow.
 *
 * Authorization code only. DigitalOcean also supports the implicit flow
 * (`response_type=token`), which puts a live credential in a URL fragment where it
 * lands in browser history and referrer headers. There is no code path here that can
 * produce it.
 */

const AUTHORIZE_URL = "https://cloud.digitalocean.com/v1/oauth/authorize";
const TOKEN_URL = "https://cloud.digitalocean.com/v1/oauth/token";

const STATE_TTL_MS = 10 * 60 * 1000;
/** One row, one id. */
export const CONNECTION_ID = "digitalocean";

/**
 * `api:read` is DigitalOcean's read-only alias and grants every read this scanner
 * needs. The granular alternative (`droplet:read firewall:read …`) is more precise but
 * undocumented for OAuth specifically — see IDEAS.md. Override to test it.
 */
const SCOPE = process.env.DO_OAUTH_SCOPE ?? "api:read";

export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export function oauthConfig(): OAuthConfig | null {
  // Both spellings accepted; neither is worth a support question.
  const clientId = (process.env.DIGITALOCEAN_CLIENT_ID ?? process.env.DO_CLIENT_ID)?.trim();
  const clientSecret = (
    process.env.DIGITALOCEAN_CLIENT_SECRET ?? process.env.DO_CLIENT_SECRET
  )?.trim();
  const redirectUri =
    (process.env.DIGITALOCEAN_REDIRECT_URI ?? process.env.DO_REDIRECT_URI)?.trim() ??
    "http://localhost:3000/api/connection/oauth/callback";

  if (!clientId || !clientSecret) return null;
  return { clientId, clientSecret, redirectUri };
}

const hashState = (state: string) => createHash("sha256").update(state).digest("hex");

/** Mint a single-use state and return the URL to send the browser to. */
export function beginAuthorization(config: OAuthConfig): string {
  const state = randomBytes(32).toString("base64url");
  const now = new Date();

  getDb()
    .insert(oauthStates)
    .values({
      stateHash: hashState(state),
      redirectUri: config.redirectUri,
      createdAt: now,
      expiresAt: new Date(now.getTime() + STATE_TTL_MS),
    })
    .run();

  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", SCOPE);
  url.searchParams.set("state", state);
  return url.toString();
}

/**
 * Consume a state, atomically.
 *
 * One statement, so a replayed callback cannot spend the same authorization twice —
 * a read-then-write would leave a window between the two.
 */
export function consumeState(state: string): { redirectUri: string } | null {
  const [row] = getDb()
    .update(oauthStates)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(oauthStates.stateHash, hashState(state)),
        isNull(oauthStates.consumedAt),
        gt(oauthStates.expiresAt, new Date()),
      ),
    )
    .returning()
    .all();

  return row ? { redirectUri: row.redirectUri } : null;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  info?: { name?: string; email?: string; uuid?: string };
  team?: { uuid?: string; name?: string };
  error?: string;
}

export class OAuthExchangeError extends Error {}

export async function exchangeCode(
  config: OAuthConfig,
  code: string,
  redirectUri: string,
): Promise<void> {
  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: config.clientId,
      client_secret: config.clientSecret,
      redirect_uri: redirectUri,
    }).toString(),
  });

  const body = (await response.json().catch(() => ({}))) as TokenResponse;

  if (!response.ok || !body.access_token) {
    // `error_description` can echo request content back; only the code is safe to show.
    throw new OAuthExchangeError(
      `DigitalOcean rejected the authorization code (${response.status}): ${body.error ?? "unknown_error"}`,
    );
  }

  const now = new Date();
  const values = {
    id: CONNECTION_ID,
    accessTokenCt: encrypt(body.access_token, "access_token"),
    refreshTokenCt: body.refresh_token ? encrypt(body.refresh_token, "refresh_token") : null,
    expiresAt: body.expires_in ? new Date(now.getTime() + body.expires_in * 1000) : null,
    grantedScopes: body.scope ?? "",
    teamName: body.team?.name ?? body.info?.email ?? null,
    teamUuid: body.team?.uuid ?? body.info?.uuid ?? null,
    createdAt: now,
    updatedAt: now,
  };

  getDb()
    .insert(oauthConnection)
    .values(values)
    .onConflictDoUpdate({ target: oauthConnection.id, set: { ...values, createdAt: undefined } })
    .run();
}

export function getOAuthConnection() {
  return (
    getDb().select().from(oauthConnection).where(eq(oauthConnection.id, CONNECTION_ID)).all()[0] ??
    null
  );
}

/** The stored access token, decrypted. Null when no OAuth connection exists. */
export function oauthAccessToken(): string | null {
  const row = getOAuthConnection();
  if (!row) return null;
  try {
    return decrypt(row.accessTokenCt, "access_token");
  } catch {
    // A key change or a corrupted row. Treat as not connected rather than crashing
    // every page that asks for a token.
    return null;
  }
}

export function disconnectOAuth(): void {
  getDb().delete(oauthConnection).where(eq(oauthConnection.id, CONNECTION_ID)).run();
}
