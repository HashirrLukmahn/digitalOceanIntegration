import { NextResponse } from "next/server";
import {
  consumeState,
  exchangeCode,
  oauthConfig,
} from "../../../../../src/oauth/digitalocean";
import { createTransport } from "../../../../../src/do/transport";
import { runSync } from "../../../../../src/sync/run";
import { logger } from "../../../../../src/lib/logger";
import { sanitizeError } from "../../../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Where DigitalOcean sends the browser back.
 *
 * The state is consumed *before* the code is redeemed, so a replayed callback cannot
 * spend the same authorization twice. Nothing sensitive is ever put in the redirect —
 * only a reason code the page turns into a sentence.
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const params = url.searchParams;

  const back = (query: string) =>
    NextResponse.redirect(new URL(`/connections/oauth?${query}`, request.url));

  const config = oauthConfig();
  if (!config) return back("error=not_configured");

  // The user declined at the consent screen, or DigitalOcean refused.
  if (params.get("error")) {
    logger.info("DigitalOcean authorization declined");
    return back("error=declined");
  }

  const code = params.get("code");
  const state = params.get("state");
  if (!code || !state) return back("error=invalid_callback");

  const consumed = consumeState(state);
  if (!consumed) {
    logger.warn("OAuth callback presented an unknown, expired, or reused state");
    return back("error=invalid_state");
  }

  try {
    await exchangeCode(config, code, consumed.redirectUri);
    logger.info("DigitalOcean connected by OAuth");
  } catch (error) {
    logger.error("OAuth code exchange failed", { error: sanitizeError(error) });
    return back("error=exchange_failed");
  }

  // Sync immediately. A connection with no snapshot behind it can show nothing, so
  // making the user press a second button to get any value from the first is a
  // pointless step. A failure here is not a failed connection — the credential is
  // stored and working, so say so and let them retry the sync.
  try {
    const result = await runSync({ http: createTransport() });
    logger.info("Initial sync after OAuth", { status: result.status });
    return back(`connected=1&synced=${result.status}`);
  } catch (error) {
    logger.warn("Connected, but the first sync failed", { error: sanitizeError(error) });
    return back("connected=1&sync_failed=1");
  }
}
