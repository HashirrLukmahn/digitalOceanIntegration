"use client";

import { useChat } from "@ai-sdk/react";
import type { UIMessage } from "ai";
import Link from "next/link";
import { Fragment, useEffect, useState } from "react";
import { HistoryDrawer } from "./history-drawer";
import { Thinking } from "./thinking";

/**
 * The assistant.
 *
 * Two things make this a security tool rather than a generic chat window. Every
 * external id it writes becomes a link to that resource's page, so a claim is one
 * click from the evidence behind it. And its tool calls are shown as they happen, so
 * a reader can see which data an answer was built from instead of trusting the prose.
 */

/** `do:droplet:12345` — the id scheme every resource shares. */
const URN = /\b(do:[a-z_]+:[A-Za-z0-9][A-Za-z0-9._-]*)/g;

function withCitations(text: string) {
  return text.split(URN).map((part, index) =>
    index % 2 === 1 ? (
      <Link
        key={index}
        href={`/inventory/${encodeURIComponent(part)}`}
        className="font-mono text-[0.85em] text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent"
      >
        {part}
      </Link>
    ) : (
      <Fragment key={index}>{part}</Fragment>
    ),
  );
}

const SUGGESTIONS = [
  "What is exposed to the internet right now?",
  "Can anything reach the database?",
  "Which resources hold sensitive data?",
  "Summarise this account's security posture.",
];

/** Named so the wait reads as progress rather than a hang. */
const TOOL_LABELS: Record<string, string> = {
  query_resources: "Reading resources",
  query_rule_findings: "Reading rule findings",
  query_relationships: "Following relationships",
  refresh_snapshot: "Re-syncing from DigitalOcean",
  report_findings: "Writing up",
};

const newThreadId = () =>
  typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : String(Date.now());

interface OpenThread {
  id: string;
  messages: UIMessage[];
}

/**
 * Owns which conversation is open; the inner component owns the conversation itself.
 *
 * The split exists because `useChat` keys its state on `id`, so changing the id and
 * seeding messages in the same render race each other — the id change wins and the
 * seeded messages are discarded. Remounting on `key={id}` sidesteps it entirely:
 * a loaded thread arrives as initial state rather than as a later mutation.
 */
export function Chat() {
  const [thread, setThread] = useState<OpenThread>(() => ({ id: newThreadId(), messages: [] }));
  const [historyKey, setHistoryKey] = useState(0);

  const startNew = () => setThread({ id: newThreadId(), messages: [] });

  const load = async (id: string) => {
    const response = await fetch(`/api/threads/${id}`);
    if (!response.ok) return;
    const body = (await response.json()) as { messages?: UIMessage[] };
    setThread({ id, messages: body.messages ?? [] });
  };

  return (
    <ChatThread
      key={thread.id}
      id={thread.id}
      initialMessages={thread.messages}
      historyKey={historyKey}
      onTurnComplete={() => setHistoryKey((k) => k + 1)}
      onSelectThread={load}
      onNewThread={startNew}
    />
  );
}

interface ThreadProps {
  id: string;
  initialMessages: UIMessage[];
  historyKey: number;
  onTurnComplete: () => void;
  onSelectThread: (id: string) => void;
  onNewThread: () => void;
}

function ChatThread({
  id,
  initialMessages,
  historyKey,
  onTurnComplete,
  onSelectThread,
  onNewThread,
}: ThreadProps) {
  const [input, setInput] = useState("");
  const { messages, sendMessage, status, error } = useChat({ id, messages: initialMessages });
  const busy = status === "submitted" || status === "streaming";

  // Refresh the drawer once a turn settles, so a new conversation gets its title.
  useEffect(() => {
    if (status === "ready" && messages.length > 0) onTurnComplete();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, messages.length]);

  const send = (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    void sendMessage({ text: trimmed });
    setInput("");
  };

  // The step the assistant is on, for the waiting label.
  const activeTool = [...messages]
    .reverse()
    .find((m) => m.role === "assistant")
    ?.parts?.filter((p) => p.type.startsWith("tool-"))
    .map((p) => TOOL_LABELS[p.type.slice("tool-".length)])
    .filter(Boolean)
    .at(-1);

  return (
    <div className="mx-auto flex min-h-[calc(100vh-13rem)] max-w-3xl flex-col">
      <div className="flex items-center justify-between py-2">
        <HistoryDrawer
          activeId={id}
          onSelect={onSelectThread}
          onNew={onNewThread}
          refreshKey={historyKey}
        />
        {messages.length > 0 && (
          <button onClick={onNewThread} className="btn-quiet">
            New conversation
          </button>
        )}
      </div>

      {messages.length === 0 ? (
        <div className="flex flex-1 flex-col justify-center py-10">
          <h1 className="text-2xl font-semibold tracking-tight">
            What would you like to know about this account?
          </h1>
          <p className="mt-2 max-w-xl text-sm leading-relaxed text-muted">
            Ask about anything in the last sync. Answers are built from the stored snapshot
            and cite the resources they rely on, so you can check the evidence yourself.
          </p>

          <div className="mt-6 grid gap-2 sm:grid-cols-2">
            {SUGGESTIONS.map((suggestion) => (
              <button
                key={suggestion}
                onClick={() => send(suggestion)}
                className="panel px-3.5 py-3 text-left text-sm transition-colors hover:border-accent"
              >
                {suggestion}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="flex-1 space-y-6 py-4">
          {messages.map((message) => (
            <div key={message.id}>
              <div className="eyebrow mb-1.5">{message.role === "user" ? "You" : "Assistant"}</div>

              {message.parts.map((part, index) => {
                if (part.type === "text") {
                  return (
                    <p
                      key={index}
                      className="whitespace-pre-wrap text-sm leading-relaxed text-ink"
                    >
                      {withCitations(part.text)}
                    </p>
                  );
                }

                if (part.type.startsWith("tool-")) {
                  const name = part.type.slice("tool-".length);
                  return (
                    <p key={index} className="my-1 font-mono text-[0.72rem] text-faint">
                      {TOOL_LABELS[name] ?? name}
                    </p>
                  );
                }

                return null;
              })}
            </div>
          ))}

          {busy && (
            <div>
              <div className="eyebrow mb-1.5">Assistant</div>
              <Thinking label={activeTool ?? "Thinking"} />
            </div>
          )}
        </div>
      )}

      {error && (
        <p className="mb-3 text-[0.8rem] text-critical">
          {error.message || "The assistant is unavailable."}
        </p>
      )}

      <form
        onSubmit={(event) => {
          event.preventDefault();
          send(input);
        }}
        className="sticky bottom-0 bg-paper pb-6 pt-3"
      >
        <div className="panel flex items-end gap-2 p-2">
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                send(input);
              }
            }}
            rows={1}
            placeholder="Ask about this account…"
            aria-label="Ask about this account"
            className="max-h-40 flex-1 resize-none bg-transparent px-2 py-1.5 text-sm text-ink outline-none placeholder:text-faint"
          />
          <button type="submit" disabled={busy || !input.trim()} className="btn-primary">
            Ask
          </button>
        </div>
        <p className="mt-2 text-[0.72rem] text-faint">
          Reads the stored snapshot, and can re-sync from DigitalOcean if you ask. It cannot
          change anything.
        </p>
      </form>
    </div>
  );
}
