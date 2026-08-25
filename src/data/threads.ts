import { desc, eq } from "drizzle-orm";
import { getDb } from "../db/client";
import { chatThreads, type ChatThreadRow } from "../db/schema";

/** First words of the opening question — enough to find a conversation again. */
export function titleFrom(messages: unknown[]): string {
  const first = messages.find(
    (m) => (m as { role?: string }).role === "user",
  ) as { parts?: Array<{ type?: string; text?: string }> } | undefined;

  const text = (first?.parts ?? [])
    .filter((p) => p.type === "text")
    .map((p) => p.text ?? "")
    .join(" ")
    .trim();

  if (!text) return "New conversation";
  return text.length > 60 ? `${text.slice(0, 60)}…` : text;
}

export function saveThread(id: string, accountId: string, messages: unknown[]): void {
  const now = new Date();
  getDb()
    .insert(chatThreads)
    .values({
      id,
      accountId,
      title: titleFrom(messages),
      messagesJson: messages,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: chatThreads.id,
      // Title is set from the first question and never rewritten, so a conversation
      // keeps the name it was found under.
      set: { messagesJson: messages, updatedAt: now },
    })
    .run();
}

export function listThreads(accountId: string, limit = 50): ChatThreadRow[] {
  return getDb()
    .select()
    .from(chatThreads)
    .where(eq(chatThreads.accountId, accountId))
    .orderBy(desc(chatThreads.updatedAt))
    .limit(limit)
    .all();
}

export function getThread(id: string): ChatThreadRow | null {
  return getDb().select().from(chatThreads).where(eq(chatThreads.id, id)).limit(1).all()[0] ?? null;
}

export function deleteThread(id: string): void {
  getDb().delete(chatThreads).where(eq(chatThreads.id, id)).run();
}
