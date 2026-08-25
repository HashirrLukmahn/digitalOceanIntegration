import { NextResponse } from "next/server";
import { runAgent } from "../../../src/agent/run";
import { getAccount } from "../../../src/data/queries";
import { sanitizeError } from "../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// The loop can take a while; well under Node's default but worth being explicit.
export const maxDuration = 120;

export async function POST() {
  const account = getAccount();
  if (!account) {
    return NextResponse.json(
      { ok: false, error: "Run a sync before analysing. The agent reads the stored snapshot." },
      { status: 409 },
    );
  }

  if (!process.env.ANTHROPIC_API_KEY) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "ANTHROPIC_API_KEY is not set. The agent needs a key of ours (separate from the " +
          "DigitalOcean token) to call the model.",
      },
      { status: 400 },
    );
  }

  try {
    const result = await runAgent({ accountId: account.id });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status: 500 });
  }
}
