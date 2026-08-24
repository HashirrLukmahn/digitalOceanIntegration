import Link from "next/link";
import { Coverage, Empty, Severity, Urn } from "../components";
import { Evidence } from "../evidence";
import {
  counts,
  findingFacets,
  getAccount,
  getLatestRun,
  inventoryFacets,
  listFindings,
} from "../../src/data/queries";
import { label } from "../labels";

export const dynamic = "force-dynamic";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export default async function ExposuresPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const account = getAccount();

  if (!account) {
    return (
      <Empty
        title="Nothing has been synced yet"
        hint="Connect a DigitalOcean account and run a sync to see exposures."
      />
    );
  }

  const run = getLatestRun(account.id);
  const facets = findingFacets(account.id);
  const types = inventoryFacets(account.id).types;
  const summary = counts(account.id);
  const findings = listFindings(account.id, {
    severity: params.severity,
    kind: params.kind,
    resourceType: params.resourceType,
  });

  const filtered = Boolean(params.severity || params.kind || params.resourceType);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Exposures</h1>
        <p className="mt-1 text-sm text-muted">
          {summary.exposed} of {summary.resources} resources are reachable from the internet.
          Every finding below states the provider value that proves it.
        </p>
      </div>

      {/* Severity distribution doubles as the filter control. */}
      <div className="flex flex-wrap items-stretch gap-2">
        {SEVERITIES.map((level) => {
          const active = params.severity === level;
          const query = new URLSearchParams(params as Record<string, string>);
          if (active) query.delete("severity");
          else query.set("severity", level);

          return (
            <Link
              key={level}
              href={`/exposures?${query.toString()}`}
              className={`panel flex min-w-[7.5rem] flex-col gap-1 px-3 py-2 hover:border-accent ${
                active ? "border-accent ring-1 ring-accent" : ""
              }`}
            >
              <Severity level={level} />
              <span className="font-mono text-xl leading-none text-ink">{summary[level]}</span>
            </Link>
          );
        })}

        {facets.kinds.length > 0 && (
          <form className="panel ml-auto flex flex-wrap items-center gap-2 px-3 py-2" action="/exposures">
            {params.severity && <input type="hidden" name="severity" value={params.severity} />}

            <label htmlFor="kind" className="eyebrow">
              Kind
            </label>
            <select id="kind" name="kind" defaultValue={params.kind ?? ""} className="field">
              <option value="">All</option>
              {facets.kinds.map((kind) => (
                <option key={kind} value={kind}>
                  {kind}
                </option>
              ))}
            </select>

            <label htmlFor="resourceType" className="eyebrow">
              Resource
            </label>
            <select
              id="resourceType"
              name="resourceType"
              defaultValue={params.resourceType ?? ""}
              className="field"
            >
              <option value="">All</option>
              {types.map((type) => (
                <option key={type} value={type}>
                  {label(type)}
                </option>
              ))}
            </select>

            <button type="submit" className="btn-quiet">
              Apply
            </button>
            {filtered && (
              <Link href="/exposures" className="text-[0.8rem] text-accent hover:underline">
                Clear
              </Link>
            )}
          </form>
        )}
      </div>

      {run && <Coverage coverage={run.coverageJson} />}

      {findings.length === 0 ? (
        <Empty
          title={filtered ? "No findings match this filter" : "No exposures found"}
          hint={
            filtered
              ? "Clear the filters to see everything that was found."
              : "Nothing assessed in this sync is reachable from the internet. Check coverage above for what was not assessed."
          }
        />
      ) : (
        <div className="space-y-2">
          {findings.map((finding) => (
            <details key={finding.id} className="panel group">
              <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 hover:bg-paper">
                <Severity level={finding.severity} />
                <span className="text-sm font-medium">{finding.title}</span>
                <Urn id={finding.resourceExternalId} />
                <span className="ml-auto font-mono text-[0.72rem] text-faint">
                  {finding.kind}
                </span>
                <span className="text-[0.78rem] text-faint group-open:hidden">Show evidence</span>
                <span className="hidden text-[0.78rem] text-faint group-open:inline">Hide</span>
              </summary>

              <div className="grid gap-6 border-t border-rule px-4 py-4 lg:grid-cols-[1.2fr_1fr]">
                <div className="space-y-4">
                  <p className="text-sm leading-relaxed">{finding.summary}</p>
                  <Evidence evidence={finding.evidenceJson} />
                </div>

                <div className="space-y-4">
                  <div>
                    <div className="eyebrow mb-1.5">Remediation</div>
                    <p className="text-sm leading-relaxed text-ink">{finding.remediation}</p>
                  </div>

                  <div>
                    <div className="eyebrow mb-1.5">Affected resource</div>
                    <Urn
                      id={finding.resourceExternalId}
                      href={`/inventory/${encodeURIComponent(finding.resourceExternalId)}`}
                    />
                  </div>

                  <div>
                    <div className="eyebrow mb-1.5">Fingerprint</div>
                    <p className="font-mono text-[0.72rem] break-all text-faint">{finding.id}</p>
                    <p className="mt-1 text-[0.78rem] text-faint">
                      Stable across syncs. First seen{" "}
                      {finding.firstSeenAt.toISOString().slice(0, 10)}.
                    </p>
                  </div>
                </div>
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}
