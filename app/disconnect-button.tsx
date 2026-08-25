"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/**
 * Ends the connection.
 *
 * Two-step rather than a modal: the first click states exactly what will be destroyed,
 * the second does it. A confirm dialog would say the same thing with more ceremony and
 * less room to say it precisely.
 */
export function DisconnectButton({ counts }: { counts: { resources: number; findings: number } }) {
  const router = useRouter();
  const [armed, setArmed] = useState(false);
  const [working, setWorking] = useState(false);

  async function run() {
    setWorking(true);
    try {
      await fetch("/api/connection/disconnect", { method: "POST" });
      router.push("/connections?reason=disconnected");
      router.refresh();
    } finally {
      setWorking(false);
    }
  }

  if (!armed) {
    return (
      <button onClick={() => setArmed(true)} className="btn-quiet">
        Disconnect
      </button>
    );
  }

  return (
    <div className="panel border-dashed px-4 py-3">
      <p className="text-sm font-medium text-ink">End the connection?</p>
      <p className="mt-0.5 text-sm text-muted">
        Deletes the stored credential, {counts.resources} synced resource
        {counts.resources === 1 ? "" : "s"}, {counts.findings} finding
        {counts.findings === 1 ? "" : "s"}, and the conversation history. The snapshot
        describes an account you would no longer be connected to, so it goes with it.
      </p>
      <div className="mt-3 flex gap-2">
        <button onClick={run} disabled={working} className="btn-primary">
          {working ? "Disconnecting…" : "Yes, disconnect"}
        </button>
        <button onClick={() => setArmed(false)} disabled={working} className="btn-quiet">
          Cancel
        </button>
      </div>
    </div>
  );
}
