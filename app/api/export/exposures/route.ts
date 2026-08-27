import { NextResponse } from "next/server";
import { NoAccountError } from "../../../../src/export/build";
import { buildExposuresExport } from "../../../../src/export/exposures";
import { sanitizeError } from "../../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const params = new URL(request.url).searchParams;
    const payload = buildExposuresExport({
      filters: {
        severity: params.get("severity") ?? undefined,
        kind: params.get("kind") ?? undefined,
        resourceType: params.get("resourceType") ?? undefined,
      },
    });
    const stamp = payload.generatedAt.slice(0, 10);

    return new NextResponse(JSON.stringify(payload, null, 2), {
      headers: {
        "content-type": "application/json",
        "content-disposition": `attachment; filename="digitalocean-exposures-${stamp}.json"`,
      },
    });
  } catch (error) {
    const status = error instanceof NoAccountError ? 409 : 500;
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status });
  }
}
