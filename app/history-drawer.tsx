"use client";

import { useEffect, useState } from "react";

/**
 * Conversation history.
 *
 * A panel that slides over the page rather than pushing it, so the answer you were
 * reading keeps its position. Closes on Escape and on backdrop click; focus moves to
 * the panel when it opens.
 */

export interface ThreadSummary {
  id: string;
  title: string;
  updatedAt: string;
}

/** Generic sidebar-toggle mark. */
function PanelIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
      <rect x="1.75" y="2.75" width="14.5" height="12.5" rx="2.25" stroke="currentColor" strokeWidth="1.4" />
      <line x1="7" y1="2.75" x2="7" y2="15.25" stroke="currentColor" strokeWidth="1.4" />
    </svg>
  );
}

function relative(iso: string): string {
  const minutes = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

interface Props {
  activeId: string;
  onSelect: (id: string) => void;
  onNew: () => void;
  /** Bumped by the parent after a turn completes, so the list picks up new titles. */
  refreshKey: number;
}

export function HistoryDrawer({ activeId, onSelect, onNew, refreshKey }: Props) {
  const [open, setOpen] = useState(false);
  const [threads, setThreads] = useState<ThreadSummary[]>([]);

  useEffect(() => {
    let cancelled = false;
    fetch("/api/threads")
      .then((r) => r.json())
      .then((body: { threads?: ThreadSummary[] }) => {
        if (!cancelled) setThreads(body.threads ?? []);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [refreshKey, open]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  async function remove(id: string) {
    await fetch(`/api/threads/${id}`, { method: "DELETE" });
    setThreads((current) => current.filter((t) => t.id !== id));
    if (id === activeId) onNew();
  }

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 rounded px-2 py-1 text-sm text-muted hover:bg-paper hover:text-ink"
        aria-label="Open conversation history"
        aria-expanded={open}
      >
        <PanelIcon />
        <span className="hidden sm:inline">History</span>
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-40 bg-ink/20"
            onClick={() => setOpen(false)}
            aria-hidden="true"
          />
          <aside
            className="fixed inset-y-0 left-0 z-50 flex w-[19rem] flex-col border-r border-rule bg-surface"
            role="dialog"
            aria-label="Conversation history"
          >
            <div className="flex items-center justify-between border-b border-rule px-4 py-3">
              <span className="text-sm font-semibold">Conversations</span>
              <button
                onClick={() => setOpen(false)}
                className="rounded px-2 py-1 text-sm text-muted hover:bg-paper hover:text-ink"
                aria-label="Close history"
              >
                ✕
              </button>
            </div>

            <div className="border-b border-rule p-3">
              <button
                onClick={() => {
                  onNew();
                  setOpen(false);
                }}
                className="btn-quiet w-full justify-center"
              >
                New conversation
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-2">
              {threads.length === 0 ? (
                <p className="px-2 py-3 text-[0.8rem] text-faint">
                  Nothing yet. Ask a question and it will be saved here.
                </p>
              ) : (
                <ul className="space-y-0.5">
                  {threads.map((thread) => (
                    <li key={thread.id} className="group flex items-center gap-1">
                      <button
                        onClick={() => {
                          onSelect(thread.id);
                          setOpen(false);
                        }}
                        className={`flex-1 rounded px-2 py-2 text-left hover:bg-paper ${
                          thread.id === activeId ? "bg-paper" : ""
                        }`}
                      >
                        <span className="block truncate text-[0.85rem] text-ink">
                          {thread.title}
                        </span>
                        <span className="text-[0.72rem] text-faint">
                          {relative(thread.updatedAt)}
                        </span>
                      </button>
                      <button
                        onClick={() => remove(thread.id)}
                        className="rounded px-1.5 py-1 text-[0.75rem] text-faint opacity-0 transition-opacity hover:text-critical focus-visible:opacity-100 group-hover:opacity-100"
                        aria-label={`Delete ${thread.title}`}
                      >
                        ✕
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </aside>
        </>
      )}
    </>
  );
}
