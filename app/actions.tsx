"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

/**
 * The two client-side controls.
 *
 * Both name the action and then report it in the same words: "Sync now" produces
 * "Synced", not "Operation complete". Failures say what happened and what to do,
 * in the interface's voice.
 */

interface SyncResponse {
  ok: boolean;
  status?: string;
  resources?: number;
  findings?: number;
  error?: string;
}

export function SyncButton({ label = "Sync now" }: { label?: string }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<SyncResponse | null>(null);

  async function sync() {
    setRunning(true);
    setResult(null);
    try {
      const response = await fetch("/api/sync", { method: "POST" });
      const body = (await response.json()) as SyncResponse;
      setResult(body);
      if (body.ok) router.refresh();
    } catch {
      setResult({ ok: false, error: "The sync request could not be sent. Is the server running?" });
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <button onClick={sync} disabled={running} className="btn-primary">
        {running ? "Syncing…" : label}
      </button>

      {result?.ok && (
        <span className="text-[0.8rem] text-muted">
          Synced. {result.resources} resources, {result.findings} findings, run{" "}
          <span className="font-mono">{result.status}</span>.
        </span>
      )}
      {result && !result.ok && (
        <span className="text-[0.8rem] text-critical">{result.error}</span>
      )}
    </div>
  );
}

interface TestResponse {
  ok: boolean;
  team?: string;
  mode?: string;
  tokenFingerprint?: string | null;
  error?: string;
}

export function TestConnectionButton() {
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResponse | null>(null);

  async function test() {
    setTesting(true);
    setResult(null);
    try {
      const response = await fetch("/api/connection/test");
      setResult((await response.json()) as TestResponse);
    } catch {
      setResult({ ok: false, error: "The test request could not be sent." });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <button onClick={test} disabled={testing} className="btn-quiet">
        {testing ? "Testing…" : "Test connection"}
      </button>

      {result?.ok && (
        <span className="text-[0.8rem] text-muted">
          Reached <span className="text-ink">{result.team}</span> in{" "}
          <span className="font-mono">{result.mode}</span> mode
          {result.tokenFingerprint ? (
            <>
              {" "}
              using token <span className="font-mono">{result.tokenFingerprint}</span>
            </>
          ) : null}
          .
        </span>
      )}
      {result && !result.ok && (
        <span className="text-[0.8rem] text-critical">{result.error}</span>
      )}
    </div>
  );
}
