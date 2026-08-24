import { NextResponse } from "next/server";
import { createTransport } from "../../../src/do/transport";
import { sanitizeError } from "../../../src/lib/redact";
import { runSync } from "../../../src/sync/run";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function POST() {
  try {
    const result = await runSync({ http: createTransport() });
    return NextResponse.json({
      ok: true,
      runId: result.runId,
      status: result.status,
      resources: result.resourcesCount,
      relationships: result.relationshipsCount,
      findings: result.findingsCount,
      coverage: result.coverage,
    });
  } catch (error) {
    // Scrubbed before it leaves the process: an upstream message could quote the
    // Authorization header back at us.
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status: 502 });
  }
}
