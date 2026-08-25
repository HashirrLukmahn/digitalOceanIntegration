import { NextResponse } from "next/server";
import { getAccount } from "../../../src/data/queries";
import { listThreads } from "../../../src/data/threads";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const account = getAccount();
  if (!account) return NextResponse.json({ threads: [] });

  return NextResponse.json({
    threads: listThreads(account.id).map((t) => ({
      id: t.id,
      title: t.title,
      updatedAt: t.updatedAt.toISOString(),
    })),
  });
}
