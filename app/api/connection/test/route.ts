import { NextResponse } from "next/server";
import { fetchTeam } from "../../../../src/do/collectors";
import { createTransport } from "../../../../src/do/transport";
import { dataSource } from "../../../../src/lib/env";
import { credentialSource, digitalOceanCredential } from "../../../../src/do/credential";
import { sanitizeError, tokenFingerprint } from "../../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Confirms the configured credential can read the account.
 *
 * Returns the team it resolved to and a fingerprint of the token -- never the token,
 * and never anything from which it could be reconstructed.
 */
export async function GET() {
  if (dataSource() === "live" && !digitalOceanCredential()) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "DIGITALOCEAN_TOKEN is not set. Add a read-only token to .env, or run with " +
          "DATA_SOURCE=fixtures to evaluate without one.",
      },
      { status: 400 },
    );
  }

  try {
    const team = await fetchTeam(createTransport());
    return NextResponse.json({
      ok: true,
      team: team.name,
      externalId: team.externalId,
      mode: dataSource(),
      tokenFingerprint: tokenFingerprint(digitalOceanCredential()),
      credentialSource: credentialSource(),
    });
  } catch (error) {
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status: 502 });
  }
}
