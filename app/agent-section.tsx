"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import type { AgentFinding, AgentOutcome } from "../src/db/schema";
import { Severity, Urn } from "./components";

/**
 * AI-flagged findings, kept visibly apart from the rule engine's.
 *
 * The dashed border is the same convention used for unassessed coverage elsewhere in
 * this interface: it marks something the tool has not proven. A reader must never
 * have to work out which findings came from a deterministic rule and which came from
 * a model — the rule engine's findings carry provider values as evidence, these carry
 * an argument.
 */

interface Props {
  latest: {
    outcome: AgentOutcome;
    steps: number;
    findings: AgentFinding[];
    error: string | null;
    startedAt: Date;
  } | null;
}

interface RunResponse {
  ok: boolean;
  outcome?: AgentOutcome;
  findings?: AgentFinding[];
  steps?: number;
  error?: string;
}

export function AgentSection({ latest }: Props) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function analyse() {
    setRunning(true);
    setError(null);
    try {
      const response = await fetch("/api/agent", { method: "POST" });
      const body = (await response.json()) as RunResponse;
      if (body.ok) router.refresh();
      else setError(body.error ?? "The analysis could not be started.");
    } catch {
      setError("The analysis request could not be sent.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">AI-flagged escalation paths</h2>
          <p className="mt-0.5 text-[0.8rem] text-muted">
            Chains spanning several resources, where each resource on its own is configured
            correctly. Reasoned, not proven — read the argument before acting.
          </p>
        </div>
        <button onClick={analyse} disabled={running} className="btn-quiet">
          {running ? "Analysing…" : latest ? "Re-analyse" : "Analyse"}
        </button>
      </div>

      {error && <p className="text-[0.8rem] text-critical">{error}</p>}

      {!latest && !error && (
        <div className="panel border-dashed px-4 py-3 text-sm text-muted">
          No analysis has run yet. This reads the stored snapshot — it makes no calls to
          DigitalOcean.
        </div>
      )}

      {latest?.outcome === "incomplete" && (
        <div className="panel border-dashed px-4 py-3">
          <p className="text-sm font-medium text-medium">Analysis incomplete</p>
          <p className="mt-0.5 text-[0.8rem] text-muted">
            The run reached its step limit after {latest.steps} steps without finishing. This is
            not a clean result — nothing was ruled out. Re-run to try again.
          </p>
        </div>
      )}

      {latest?.outcome === "failed" && (
        <div className="panel border-dashed px-4 py-3">
          <p className="text-sm font-medium text-critical">Analysis failed</p>
          <p className="mt-0.5 font-mono text-[0.78rem] text-muted">{latest.error}</p>
        </div>
      )}

      {latest?.outcome === "completed" && latest.findings.length === 0 && (
        <div className="panel border-dashed px-4 py-3 text-sm">
          <span className="font-medium text-ok">No escalation paths found.</span>{" "}
          <span className="text-muted">
            The analysis completed in {latest.steps} steps and found no chain spanning multiple
            resources. This is the expected result for most accounts.
          </span>
        </div>
      )}

      {latest?.outcome === "completed" &&
        latest.findings.map((finding, index) => (
          <details key={index} className="panel border-dashed">
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 hover:bg-paper">
              <Severity level={finding.severity} />
              <span className="text-sm font-medium">{finding.title}</span>
              <span className="ml-auto text-micro uppercase tracking-[0.08em] text-faint">
                AI-flagged · not verified
              </span>
            </summary>

            <div className="space-y-4 border-t border-dashed border-rule px-4 py-4">
              <div>
                <div className="eyebrow mb-1.5">Reasoning</div>
                <p className="text-sm leading-relaxed">{finding.reasoning}</p>
              </div>

              <div>
                <div className="eyebrow mb-1.5">Resources in the chain</div>
                <div className="flex flex-wrap gap-x-4 gap-y-1">
                  {finding.resourceExternalIds.map((id) => (
                    <Urn key={id} id={id} href={`/inventory/${encodeURIComponent(id)}`} />
                  ))}
                </div>
              </div>

              {finding.supportingFindingKinds.length > 0 && (
                <div>
                  <div className="eyebrow mb-1.5">Builds on these rule findings</div>
                  <div className="flex flex-wrap gap-2">
                    {finding.supportingFindingKinds.map((kind) => (
                      <span key={kind} className="font-mono text-[0.72rem] text-muted">
                        {kind}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </details>
        ))}
    </section>
  );
}
