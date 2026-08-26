import { externalId } from "../../normalize/resource";
import { isPublicInternetCidr } from "../ports";
import { deriveSeverity, severityEvidence } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * Managed database exposure.
 *
 * DigitalOcean database clusters get a public hostname by default; access is
 * controlled by "trusted sources", which are per-droplet, per-tag, per-k8s-cluster,
 * per-app, or per-IP. Notably there is **no VPC trusted-source type**, so this code
 * never claims a database "trusts the whole VPC" -- the API cannot express it and the
 * claim would be unfalsifiable.
 *
 * Both rules distinguish *no trusted sources* from *trusted sources unknown*. If the
 * per-cluster firewall fetch failed, the cluster is absent from `databaseFirewalls`
 * and neither rule fires. Guessing there would mean reporting a locked-down database
 * as world-readable on the strength of a transient 500.
 */

/** A cluster with a public endpoint and no trusted sources at all. */
export const databasePublicNoTrustedSourcesRule: ExposureRule = {
  kind: "database.public_no_trusted_sources",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const cluster of inventory.databases) {
      const host = cluster.connection?.host;
      if (!host) continue; // no public connection endpoint

      const rules = inventory.databaseFirewalls[cluster.id];
      if (rules === undefined) continue; // unknown, not empty -- see module comment
      if (rules.length > 0) continue;

      // Derived: the public endpoint is reported, but the *absence* of trusted sources is
      // inferred from a firewall list that returned successfully and was empty.
      const derivation = deriveSeverity("datastore", "sensitive_ports");

      findings.push({
        resourceExternalId: externalId("database", cluster.id),
        kind: "database.public_no_trusted_sources",
        severity: derivation.final,
        confidence: "derived",
        provesInternetExposure: true,
        title: "Managed database is reachable from the internet with no trusted sources",
        summary:
          `Database cluster "${cluster.name}" (${cluster.engine ?? "unknown engine"}) exposes a ` +
          `public endpoint at ${host}:${cluster.connection?.port ?? "?"} and has no trusted ` +
          `sources configured, so any host on the internet can open a connection and attempt ` +
          `to authenticate.`,
        evidence: {
          ...severityEvidence("derived", derivation),
          publicHost: host,
          publicPort: cluster.connection?.port ?? null,
          engine: cluster.engine ?? null,
          version: cluster.version ?? null,
          trustedSourceCount: 0,
          privateNetworkUuid: cluster.private_network_uuid ?? null,
          hasPrivateEndpoint: Boolean(cluster.private_connection?.host),
        },
        remediation:
          "Add trusted sources restricting the cluster to the droplets, tags, apps, or " +
          "Kubernetes clusters that need it, and connect over the private network endpoint " +
          "where possible.",
        stableElement: "public-endpoint-no-trusted-sources",
        // Depends on both the cluster listing and this cluster's trusted-source fetch, so it
        // reconciles only when both were authoritative -- an empty trusted-source list is
        // only meaningful if the firewall call actually succeeded.
        coverageKeys: ["databases", `database_firewall:${cluster.id}`],
      });
    }

    return findings;
  },
};

/** A cluster whose trusted sources include the entire internet. */
export const databaseTrustedSourceIsPublicRule: ExposureRule = {
  kind: "database.trusted_source_is_public",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const cluster of inventory.databases) {
      const rules = inventory.databaseFirewalls[cluster.id];
      if (rules === undefined || rules.length === 0) continue;

      const publicRules = rules.filter(
        (rule) => rule.type === "ip_addr" && isPublicInternetCidr(rule.value),
      );
      if (publicRules.length === 0) continue;

      const host = cluster.connection?.host ?? null;

      // Provider_reported: the 0.0.0.0/0 trusted source is a value DigitalOcean returned.
      const derivation = deriveSeverity("datastore", "sensitive_ports");

      findings.push({
        resourceExternalId: externalId("database", cluster.id),
        kind: "database.trusted_source_is_public",
        severity: derivation.final,
        confidence: "provider_reported",
        provesInternetExposure: true,
        title: "Managed database trusts the entire internet",
        summary:
          `Database cluster "${cluster.name}" has a trusted source of ` +
          `${publicRules.map((r) => r.value).join(", ")}, which allows connections from any ` +
          `address. The trusted-source list is present but does not restrict anything.`,
        evidence: {
          ...severityEvidence("provider_reported", derivation),
          publicHost: host,
          publicPort: cluster.connection?.port ?? null,
          engine: cluster.engine ?? null,
          trustedSourceCount: rules.length,
          publicTrustedSources: publicRules.map((r) => ({
            type: r.type,
            value: r.value,
            uuid: r.uuid ?? null,
          })),
          // Shown so the reviewer can see what would remain after removing the open rule.
          otherTrustedSources: rules
            .filter((r) => !publicRules.includes(r))
            .map((r) => ({ type: r.type, value: r.value })),
        },
        remediation:
          "Remove the 0.0.0.0/0 (or ::/0) trusted source and replace it with the specific " +
          "droplets, tags, apps, or address ranges that need database access.",
        stableElement: publicRules
          .map((r) => `${r.type}:${r.value}`)
          .sort()
          .join("|"),
        coverageKeys: ["databases", `database_firewall:${cluster.id}`],
      });
    }

    return findings;
  },
};
