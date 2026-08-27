import { NextResponse } from "next/server";
import { NoAccountError } from "../../../../src/export/build";
import { loadSnapshotExport, NoSnapshotError } from "../../../../src/export/snapshot";
import { sanitizeError } from "../../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const syncRunId = new URL(request.url).searchParams.get("syncRunId") ?? undefined;
    const document = loadSnapshotExport({ syncRunId });

    return new NextResponse(JSON.stringify(document, null, 2), {
      headers: {
        "content-type": "application/json",
        // Named by the run it captures, so a downloaded snapshot is self-identifying.
        "content-disposition": `attachment; filename="do-snapshot-${document.syncRunId}.json"`,
      },
    });
  } catch (error) {
    const status = error instanceof NoAccountError || error instanceof NoSnapshotError ? 409 : 500;
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status });
  }
}
