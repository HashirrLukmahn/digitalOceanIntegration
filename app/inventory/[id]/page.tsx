import Link from "next/link";
import { notFound } from "next/navigation";
import { Empty, Exposed, Field, Sensitivity, Severity, Urn } from "../../components";
import { Evidence } from "../../evidence";
import { RemediationBlock } from "../../remediation";
import { label } from "../../labels";
import {
  findingsForResource,
  getAccount,
  getResource,
  getResourceEdges,
  resolveNames,
} from "../../../src/data/queries";

export const dynamic = "force-dynamic";

const RELATIONSHIP_PHRASING: Record<string, { out: string; in: string }> = {
  contains: { out: "contains", in: "is contained by" },
  attached_to: { out: "is attached to", in: "has attached" },
  routes_to: { out: "routes to", in: "receives traffic from" },
  depends_on: { out: "depends on", in: "is depended on by" },
};

export default async function ResourcePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const externalId = decodeURIComponent(id);
  const account = getAccount();
  if (!account) return <Empty title="Nothing has been synced yet" hint="Run a sync first." />;

  const resource = getResource(account.id, externalId);
  if (!resource) notFound();

  const { outgoing, incoming } = getResourceEdges(account.id, externalId);
  const names = resolveNames(account.id, [
    ...outgoing.map((e) => e.targetExternalId),
    ...incoming.map((e) => e.sourceExternalId),
  ]);
  const findings = findingsForResource(account.id, externalId);

  const metadata = Object.entries(resource.metadataJson);
  const tags = Object.entries(resource.tagsJson);

  return (
    <div className="space-y-6">
      <div>
        <Link href="/inventory" className="text-[0.8rem] text-accent hover:underline">
          ← Inventory
        </Link>
        <h1 className="mt-2 text-lg font-semibold tracking-tight">{resource.name}</h1>
        <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1">
          <Urn id={resource.externalId} />
          <span className="text-[0.8rem] text-muted">{label(resource.resourceType)}</span>
          <Exposed value={resource.isInternetExposed} />
        </div>
      </div>

      <div className="panel grid gap-5 px-4 py-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field label="Region">
          <span className="font-mono text-[0.8rem]">{resource.region ?? "—"}</span>
        </Field>
        <Field label="State">
          <span className="font-mono text-[0.8rem]">{resource.state ?? "—"}</span>
        </Field>
        <Field label="Sensitivity">
          <Sensitivity value={resource.sensitivity} />
        </Field>
        <Field label="Last seen">
          <span className="font-mono text-[0.8rem]">
            {resource.lastSeenAt.toISOString().slice(0, 10)}
          </span>
        </Field>
      </div>

      {findings.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Findings ({findings.length})</h2>
          {findings.map((finding) => (
            <details key={finding.id} className="panel">
              <summary className="flex cursor-pointer list-none flex-wrap items-center gap-4 px-4 py-3 hover:bg-paper">
                <Severity level={finding.severity} />
                <span className="text-sm font-medium">{finding.title}</span>
                <span className="ml-auto font-mono text-[0.72rem] text-faint">{finding.kind}</span>
              </summary>
              <div className="space-y-4 border-t border-rule px-4 py-4">
                <p className="text-sm leading-relaxed">{finding.summary}</p>
                <Evidence evidence={finding.evidenceJson} />
                <div>
                  <div className="eyebrow mb-1.5">Remediation</div>
                  <p className="text-sm leading-relaxed">{finding.remediation}</p>
                  <RemediationBlock
                    kind={finding.kind}
                    resourceExternalId={finding.resourceExternalId}
                    evidence={finding.evidenceJson}
                  />
                </div>
              </div>
            </details>
          ))}
        </section>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <h2 className="mb-2 text-sm font-semibold">Configuration</h2>
          {metadata.length === 0 ? (
            <div className="panel px-4 py-3 text-sm text-faint">
              No allowlisted metadata for this resource type.
            </div>
          ) : (
            <div className="panel px-4 py-3">
              {metadata.map(([key, value]) => (
                <div key={key} className="flex gap-3 border-b border-rule py-1.5 last:border-0">
                  <span className="w-52 flex-none text-[0.78rem] text-faint">{key}</span>
                  <span className="font-mono text-[0.78rem] break-all">
                    {Array.isArray(value)
                      ? value.join(", ")
                      : typeof value === "boolean"
                        ? value
                          ? "yes"
                          : "no"
                        : String(value)}
                  </span>
                </div>
              ))}
            </div>
          )}

          {tags.length > 0 && (
            <div className="mt-4">
              <div className="eyebrow mb-1.5">Tags</div>
              <div className="flex flex-wrap gap-1.5">
                {tags.map(([key, value]) => (
                  <span
                    key={key}
                    className="rounded border border-rule bg-surface px-2 py-0.5 font-mono text-[0.72rem]"
                  >
                    {value ? `${key}:${value}` : key}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>

        <section>
          <h2 className="mb-2 text-sm font-semibold">Relationships</h2>
          {outgoing.length === 0 && incoming.length === 0 ? (
            <div className="panel px-4 py-3 text-sm text-faint">
              No relationships were reported or derived for this resource.
            </div>
          ) : (
            <div className="panel divide-y divide-rule">
              {[
                ...outgoing.map((edge) => ({ edge, direction: "out" as const })),
                ...incoming.map((edge) => ({ edge, direction: "in" as const })),
              ].map(({ edge, direction }) => {
                const other =
                  direction === "out" ? edge.targetExternalId : edge.sourceExternalId;
                const phrase =
                  RELATIONSHIP_PHRASING[edge.relationship]?.[direction] ?? edge.relationship;

                return (
                  <div key={edge.id} className="flex flex-wrap items-baseline gap-x-2 px-4 py-2">
                    <span className="text-[0.8rem] text-muted">{phrase}</span>
                    <Link
                      href={`/inventory/${encodeURIComponent(other)}`}
                      className="text-sm font-medium hover:text-accent hover:underline"
                    >
                      {names.get(other) ?? other}
                    </Link>
                    <Urn id={other} />
                    <span
                      className={`ml-auto text-micro uppercase tracking-[0.08em] ${
                        edge.evidence === "provider_reported" ? "text-ok" : "text-faint"
                      }`}
                      title={
                        edge.evidence === "provider_reported"
                          ? "Reported directly by DigitalOcean"
                          : "Derived by this tool from two reported facts"
                      }
                    >
                      {edge.evidence === "provider_reported" ? "reported" : "derived"}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
