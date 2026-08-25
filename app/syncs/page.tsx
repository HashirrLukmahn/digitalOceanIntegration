import { requireConnection } from "../../src/connection/state";
import { SyncButton } from "../actions";
import { Empty, StatusPill, formatTime } from "../components";
import { getAccount, listRuns } from "../../src/data/queries";

export const dynamic = "force-dynamic";

export default function SyncsPage() {
  requireConnection();

  const account = getAccount();
  if (!account) {
    return <Empty title="Nothing has been synced yet" hint="Run a sync to create a history." />;
  }

  const runs = listRuns(account.id);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold tracking-tight">Syncs</h1>
          <p className="mt-1 text-sm text-muted">
            Every attempt, including the ones that only partly succeeded.
          </p>
        </div>
        <SyncButton />
      </div>

      <div className="space-y-2">
        {runs.map((run) => {
          const coverage = run.coverageJson;
          const gaps = [
            ...(coverage.failedCollectors ?? []).map((c) => ({ ...c, kind: "failed" })),
            ...(coverage.unavailableCollectors ?? []).map((c) => ({ ...c, kind: "unavailable" })),
          ];

          return (
            <div key={run.id} className="panel px-4 py-3">
              <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
                <StatusPill status={run.status} />
                <span className="font-mono text-[0.78rem] text-muted">
                  {formatTime(run.startedAt)}
                </span>
                <span className="text-[0.8rem] text-muted">
                  {run.resourcesCount} resources · {run.relationshipsCount} relationships ·{" "}
                  {run.findingsCount} findings
                </span>
                <span className="ml-auto font-mono text-[0.72rem] text-faint">{run.id}</span>
              </div>

              {run.error && (
                <p className="mt-2 font-mono text-[0.78rem] text-critical">{run.error}</p>
              )}

              <div className="mt-3 grid gap-4 sm:grid-cols-2">
                <div>
                  <div className="eyebrow mb-1.5">Collected</div>
                  <div className="flex flex-wrap gap-1.5">
                    {coverage.completedCollectors.map((name) => (
                      <span
                        key={name}
                        className="rounded border border-rule bg-surface px-2 py-0.5 font-mono text-[0.72rem] text-ink"
                      >
                        {name}
                      </span>
                    ))}
                  </div>
                </div>

                {gaps.length > 0 && (
                  <div>
                    <div className="eyebrow mb-1.5">Not collected</div>
                    <ul className="space-y-1.5">
                      {gaps.map((gap) => (
                        <li key={gap.collector} className="text-[0.8rem]">
                          <span className="unknown">{gap.collector}</span>
                          <span className="text-faint"> {gap.kind}</span>
                          <p className="mt-0.5 leading-snug text-muted">{gap.message}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
