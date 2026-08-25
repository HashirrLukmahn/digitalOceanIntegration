import { NextResponse } from "next/server";
import { deleteThread, getThread } from "../../../../src/data/threads";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  const thread = getThread(id);
  if (!thread) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return NextResponse.json({ id: thread.id, title: thread.title, messages: thread.messagesJson });
}

export async function DELETE(_request: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  deleteThread(id);
  return NextResponse.json({ ok: true });
}
