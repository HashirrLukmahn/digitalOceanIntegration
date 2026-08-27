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
  category: "attack_path",
  // The trust half needs the database listing and its firewall; the exposure half needs
  // whatever proved the workload public. Requiring the common collectors keeps a path from
  // being asserted on a run where the firewall or droplet data was missing.
  requires: ["databases", "droplets", "firewalls"],
  references: ["https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/"],
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

/**
 * A datastore whose access credential is stored in plaintext on an internet-exposed app
 * that depends on it.
 *
 * This is a DigitalOcean-specific escalation the network-trust path misses. App Platform
 * injects a managed database's connection string into the app's environment; if that
 * variable is left `GENERAL` (plaintext) rather than `SECRET`, the credential is readable
 * by anyone with spec access -- every team member, every CI job, every connected tool --
 * and the app itself is on the public internet. So the datastore is reachable two ways at
 * once: read the plaintext credential, or compromise the public app that holds it. It fires
 * only when all three facts line up (public app + plaintext-secret finding + a depends_on
 * edge to a datastore), which is what keeps it off the many apps that legitimately hold a
 * *secret*-typed credential. Confidence `derived`; the finding sits on the datastore.
 */
export const exposedAppLeaksDatastoreCredentialRule: PathRule = {
  kind: "path.exposed_app_leaks_datastore_credential",
  category: "attack_path",
  requires: ["apps", "databases"],
  references: [
    "https://docs.digitalocean.com/products/app-platform/how-to/use-environment-variables/",
    "https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/",
  ],
  evaluate({ relationships, exposedResourceIds, findingsByResource, inventory }) {
    const findings: DraftFinding[] = [];
    const byDatastore = new Map<string, string[]>();

    for (const edge of relationships) {
      if (edge.relationship !== "depends_on") continue;
      const app = edge.sourceExternalId;
      const datastore = edge.targetExternalId;
      // The depends_on edges are app -> database; guard the target type explicitly.
      if (resourceTypeFromExternalId(datastore) !== "digitalocean.database_cluster") continue;
      // The app must be internet-exposed *and* have a plaintext-secret finding: a public app
      // holding a properly SECRET-typed credential is normal and is not reported.
      if (!exposedResourceIds.has(app)) continue;
      const appFindings = findingsByResource.get(app) ?? [];
      if (!appFindings.some((f) => f.kind === "app.plaintext_secret_env")) continue;

      const list = byDatastore.get(datastore) ?? [];
      list.push(app);
      byDatastore.set(datastore, list);
    }

    for (const [datastore, apps] of byDatastore) {
      const clusterId = datastore.split(":").slice(2).join(":");
      const cluster = inventory.databases.find((c) => c.id === clusterId);
      const name = cluster?.name ?? datastore;

      findings.push({
        resourceExternalId: datastore,
        kind: "path.exposed_app_leaks_datastore_credential",
        severity: "high",
        confidence: "derived",
        provesInternetExposure: false,
        title: "Datastore credential is stored in plaintext on an internet-exposed app",
        summary:
          `Datastore "${name}" is depended on by ${apps.length} internet-exposed App Platform ` +
          `app(s) (${apps.join(", ")}) that store credential-shaped environment variables in ` +
          `plaintext (GENERAL rather than SECRET). The datastore's access credential is therefore ` +
          `readable by anyone with app-spec access and is held on a public app, so the datastore is ` +
          `reachable both by reading the plaintext value and by compromising the exposed app.`,
        evidence: {
          confidence: "derived",
          severityRationale: {
            base: "high",
            modifiers: [],
            final: "high",
            formula:
              "internet-exposed app + plaintext credential + depends_on datastore ⇒ credential disclosure and pivot ⇒ high",
          },
          datastore,
          exposedApps: apps,
        },
        remediation:
          "Change the app's database credential variables to type SECRET so DigitalOcean " +
          "encrypts them, rotate the exposed credential, and prefer the database's private " +
          "connection endpoint. Confirm the app's public routes do not expose the credential.",
        stableElement: `app-credential-leak:${apps.slice().sort().join(",")}`,
        coverageKeys: ["apps", "databases"],
      });
    }

    return findings;
  },
};
