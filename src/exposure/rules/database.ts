import { externalId } from "../../normalize/resource";
import { isPublicInternetCidr } from "../ports";
import { deriveSeverity, severityEvidence, type Severity } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

/** Parse a provider `YYYY-MM-DD` lifecycle date to a Date, or null if absent/malformed. */
function parseLifecycleDate(value: string | undefined): Date | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

const DAY_MS = 86_400_000;

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

/**
 * A managed database running an engine version at or near end of life.
 *
 * Entirely provider-reported: DigitalOcean returns `version_end_of_life` (patches stop)
 * and `version_end_of_availability` (no new clusters) per cluster, so there is no
 * hand-maintained lifecycle table to drift out of date. Severity tiers by urgency:
 *
 *   past end of life        high    -- the version no longer receives security patches
 *   end of life <= 90 days  medium  -- imminent; schedule the upgrade now
 *   end of availability due  low     -- still supported, but plan a move off the version
 *
 * This is a lifecycle/patch-hygiene finding, not a reachability one, so it never marks the
 * cluster internet-exposed; a separate rule decides whether the cluster is reachable.
 */
export const databaseVersionEndOfLifeRule: ExposureRule = {
  kind: "database.version_end_of_life",
  evaluate({ inventory, now }) {
    const findings: DraftFinding[] = [];
    const nowMs = now.getTime();

    for (const cluster of inventory.databases) {
      const eol = parseLifecycleDate(cluster.version_end_of_life);
      const eoa = parseLifecycleDate(cluster.version_end_of_availability);
      if (!eol && !eoa) continue;

      const isPast = (date: Date | null) => date !== null && date.getTime() <= nowMs;
      const withinDays = (date: Date | null, days: number) =>
        date !== null && date.getTime() > nowMs && date.getTime() - nowMs <= days * DAY_MS;

      let severity: Severity;
      let situation: string;
      if (isPast(eol)) {
        severity = "high";
        situation = `reached end of life on ${cluster.version_end_of_life} and no longer receives security patches`;
      } else if (withinDays(eol, 90)) {
        severity = "medium";
        situation = `reaches end of life on ${cluster.version_end_of_life}, within 90 days`;
      } else if (isPast(eoa) || withinDays(eoa, 90)) {
        severity = "low";
        situation = `has reached or is nearing end of availability (${cluster.version_end_of_availability}); it is still supported, but plan an upgrade`;
      } else {
        continue; // dates exist but are comfortably in the future
      }

      const engine = cluster.engine ?? "unknown engine";
      findings.push({
        resourceExternalId: externalId("database", cluster.id),
        kind: "database.version_end_of_life",
        severity,
        confidence: "provider_reported",
        provesInternetExposure: false,
        title: `Managed database runs an ${severity === "low" ? "aging" : "end-of-life"} engine version`,
        summary:
          `Database cluster "${cluster.name}" runs ${engine} ${cluster.version ?? "?"}, which ` +
          `${situation}. Running an unsupported engine version means security fixes are no ` +
          `longer applied, so schedule an in-place upgrade to a supported version.`,
        evidence: {
          confidence: "provider_reported",
          severityRationale: {
            base: severity,
            modifiers: [],
            final: severity,
            formula: `engine version lifecycle: ${situation} ⇒ ${severity}`,
          },
          engine: cluster.engine ?? null,
          version: cluster.version ?? null,
          versionEndOfLife: cluster.version_end_of_life ?? null,
          versionEndOfAvailability: cluster.version_end_of_availability ?? null,
        },
        remediation:
          "Upgrade the cluster to a supported engine version in the DigitalOcean control " +
          "panel or via the API. Test against the target version first; major-version " +
          "upgrades can require application changes.",
        // One ongoing finding per cluster: as the situation escalates from low to high the
        // same finding is updated in place, preserving first_seen_at.
        stableElement: "version-lifecycle",
        coverageKeys: ["databases"],
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
