import { NextResponse } from "next/server";
import { agentApiKey, MISSING_KEY_MESSAGE } from "../../../src/agent/model";
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

  if (!agentApiKey()) {
    return NextResponse.json({ ok: false, error: MISSING_KEY_MESSAGE }, { status: 400 });
  }

  try {
    const result = await runAgent({ accountId: account.id });
    return NextResponse.json({ ok: true, ...result });
  } catch (error) {
    return NextResponse.json({ ok: false, error: sanitizeError(error) }, { status: 500 });
  }
}
