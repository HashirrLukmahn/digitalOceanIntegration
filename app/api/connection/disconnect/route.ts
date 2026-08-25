import { NextResponse } from "next/server";
import { disconnect } from "../../../../src/connection/disconnect";
import { logger } from "../../../../src/lib/logger";
import { sanitizeError } from "../../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** POST only: this destroys data, so it must not be reachable by following a link. */
export async function POST() {
  try {
    const result = disconnect();
    logger.info("Connection ended", { ...result });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status: 500 });
  }
}
