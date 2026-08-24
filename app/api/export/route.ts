import { NextResponse } from "next/server";
import { buildExport, NoAccountError } from "../../../src/export/build";
import { sanitizeError } from "../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  try {
    const includeRemoved = new URL(request.url).searchParams.get("includeRemoved") === "true";
    const payload = buildExport({ includeRemoved });
    const stamp = payload.generatedAt.slice(0, 10);

    return new NextResponse(JSON.stringify(payload, null, 2), {
      headers: {
        "content-type": "application/json",
        "content-disposition": `attachment; filename="digitalocean-security-export-${stamp}.json"`,
      },
    });
  } catch (error) {
    const status = error instanceof NoAccountError ? 409 : 500;
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status });
  }
}
