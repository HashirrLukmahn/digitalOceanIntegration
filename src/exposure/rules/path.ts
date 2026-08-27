import { resourceTypeFromExternalId } from "../../normalize/resource";
import type { DraftFinding, PathRule } from "../types";

/**
 * The first deterministic cross-resource path: an internet-exposed workload that a
 * datastore trusts.
 *
 * Each piece is individually fine. A droplet with a public service is normal. A database
 * whose trusted sources name that droplet is normal -- that is how you are *supposed* to
 * grant a workload database access. The danger is the combination: if the public workload
 * is compromised, the attacker inherits its trust and reaches the database, even though the
 * database is never directly exposed to the internet. That is the "each resource on its own
 * looks correctly configured" case the LLM agent hunts for -- made deterministic here,
 * because both halves are now facts the engine already computed:
 *
 *   - phase one decided the workload is internet-exposed (`exposedResourceIds`), and
 *   - the `trusts` edge says the datastore admits that workload.
 *
 * The finding is attached to the datastore (the asset at risk) and is *not* marked
 * internet-exposed: the datastore's exposure is indirect, through the pivot, and calling it
 * directly exposed would corrupt the meaning of that column. Confidence is `derived` --
 * it combines the exposure finding and the trust edge, more than one provider fact.
 */
export const publicWorkloadToDatastoreRule: PathRule = {
  kind: "path.public_workload_to_datastore",
  evaluate({ inventory, relationships, exposedResourceIds }) {
    // Group exposed trusted workloads by the datastore that trusts them: one finding per
    // datastore, listing every internet-exposed entry point into it.
    const byDatastore = new Map<
      string,
      Array<{ workload: string; trustForm: unknown; edgeEvidence: string }>
    >();

    for (const edge of relationships) {
      if (edge.relationship !== "trusts") continue;
      // The trusts edge is truster -> trusted: source is the datastore, target the workload.
      // Today every trusts edge is database-sourced; assert it so a future trust edge with a
      // different source type cannot silently produce a wrong cluster lookup or coverage key.
      if (resourceTypeFromExternalId(edge.sourceExternalId) !== "digitalocean.database_cluster") continue;
      if (!exposedResourceIds.has(edge.targetExternalId)) continue;

      const list = byDatastore.get(edge.sourceExternalId) ?? [];
      list.push({
        workload: edge.targetExternalId,
        trustForm: (edge.metadata as { form?: unknown }).form ?? null,
        edgeEvidence: edge.evidence,
      });
      byDatastore.set(edge.sourceExternalId, list);
    }

    const findings: DraftFinding[] = [];

    for (const [datastore, entries] of byDatastore) {
      const clusterId = datastore.split(":").slice(2).join(":");
      const cluster = inventory.databases.find((c) => c.id === clusterId);
      const name = cluster?.name ?? datastore;

      // coverageKeys: the trust half (the datastore listing plus this cluster's firewall),
      // and the datasets that established each exposed workload.
      const coverageKeys = new Set<string>(["databases", `database_firewall:${clusterId}`]);
      for (const entry of entries) {
        const type = resourceTypeFromExternalId(entry.workload);
        if (type) coverageKeys.add(type);
      }

      findings.push({
        resourceExternalId: datastore,
        kind: "path.public_workload_to_datastore",
        severity: "high",
        confidence: "derived",
        provesInternetExposure: false,
        title: "Internet-exposed workload can reach a trusted datastore",
        summary:
          `Datastore "${name}" trusts ${entries.length} workload(s) that are themselves ` +
          `internet-exposed (${entries.map((e) => e.workload).join(", ")}). An attacker who ` +
          `compromises one of those public entry points inherits its trusted access and reaches ` +
          `the datastore, even though the datastore is not directly exposed to the internet. ` +
          `Neither the public workload nor the database trust is wrong on its own; together they ` +
          `form a path from the internet to the data.`,
        evidence: {
          confidence: "derived",
          severityRationale: {
            base: "high",
            modifiers: [],
            final: "high",
            formula:
              "internet-exposed workload → datastore trust edge → datastore reachable on compromise ⇒ high",
          },
          datastore,
          exposedEntryPoints: entries.map((e) => ({
            workload: e.workload,
            trustForm: e.trustForm,
            edgeEvidence: e.edgeEvidence,
          })),
        },
        remediation:
          "Break the path at either end: remove the internet exposure of the trusted " +
          "workload(s) (restrict their firewall or remove the public ingress), or narrow the " +
          "database's trusted sources so that a compromised public host does not inherit " +
          "database access. Prefer connecting over the private network.",
        stableElement: `exposed-trust:${entries
          .map((e) => e.workload)
          .sort()
          .join(",")}`,
        coverageKeys: [...coverageKeys],
      });
    }

    return findings;
  },
};
