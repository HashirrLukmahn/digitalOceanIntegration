import { NextResponse } from "next/server";
import {
  consumeState,
  exchangeCode,
  oauthConfig,
} from "../../../../../src/oauth/digitalocean";
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
    return back("connected=1");
  } catch (error) {
    logger.error("OAuth code exchange failed", { error: sanitizeError(error) });
    return back("error=exchange_failed");
  }
}
