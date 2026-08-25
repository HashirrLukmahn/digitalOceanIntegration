import { NextResponse } from "next/server";
import { beginAuthorization, oauthConfig } from "../../../../../src/oauth/digitalocean";
import { hasMasterKey } from "../../../../../src/oauth/crypto";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Starts the flow: mints a single-use state, then hands the browser to DigitalOcean. */
export async function GET(request: Request) {
  const back = (reason: string) =>
    NextResponse.redirect(new URL(`/connections/oauth?error=${reason}`, request.url));

  if (!oauthConfig()) return back("not_configured");
  // Checked before leaving rather than on return: sending someone to DigitalOcean only
  // to fail on the way back, after they have approved, is a worse experience.
  if (!hasMasterKey()) return back("no_master_key");

  return NextResponse.redirect(beginAuthorization(oauthConfig()!));
}
