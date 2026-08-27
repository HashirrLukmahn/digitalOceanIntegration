import { PATH_RULES, RULES } from "./engine";
import type { RuleContract } from "./types";

/**
 * Where a finding's data came from.
 *
 * Confidence says *how sure* we are; this says *what we read to be sure*. Every finding
 * records the collector coverage keys it depended on (or, for a rule that reads a single
 * collector, the rule's declared `requires`), and each of those maps to a concrete
 * DigitalOcean API call. Surfacing the exact endpoints -- `GET /v2/databases`,
 * `GET /v2/databases/<id>/firewall` -- means a reader can reproduce the evidence, not take
 * the provenance on trust.
 */

const RULE_INDEX: Map<string, RuleContract> = new Map(
  [...RULES, ...PATH_RULES].map((rule) => [rule.kind, rule]),
);

/** Collector name -> the DigitalOcean endpoint it lists. */
const COLLECTOR_ENDPOINT: Record<string, string> = {
  projects: "GET /v2/projects",
  droplets: "GET /v2/droplets",
  firewalls: "GET /v2/firewalls",
  load_balancers: "GET /v2/load_balancers",
  vpcs: "GET /v2/vpcs",
  databases: "GET /v2/databases",
  kubernetes: "GET /v2/kubernetes/clusters",
  apps: "GET /v2/apps",
  volumes: "GET /v2/volumes",
  container_registries: "GET /v2/registries",
  certificates: "GET /v2/certificates",
  reserved_ips: "GET /v2/reserved_ips",
  domains: "GET /v2/domains",
  spaces: "Anonymous public-read probe (S3-compatible API)",
};

/** Resolve one coverage key to the API call that produced it, or null if not mappable. */
function endpointForKey(key: string): string | null {
  if (COLLECTOR_ENDPOINT[key]) return COLLECTOR_ENDPOINT[key];

  const colon = key.indexOf(":");
  if (colon === -1) return null;
  const prefix = key.slice(0, colon);
  const id = key.slice(colon + 1);
  if (!id) return null;

  switch (prefix) {
    case "database_firewall":
      return `GET /v2/databases/${id}/firewall`;
    case "kubernetes_upgrades":
      return `GET /v2/kubernetes/clusters/${id}/upgrades`;
    case "dns_records":
      return `GET /v2/domains/${id}/records`;
    default:
      return null;
  }
}

/**
 * The API calls behind a finding.
 *
 * Prefers the finding's own `coverageKeys` (specific, e.g. one cluster's firewall) and
 * falls back to the rule's declared `requires` for findings that read a single collector
 * and did not record granular keys.
 */
export function apiCallsForFinding(kind: string, coverageKeys: readonly string[]): string[] {
  const keys = coverageKeys.length > 0 ? coverageKeys : RULE_INDEX.get(kind)?.requires ?? [];
  const calls = keys.map(endpointForKey).filter((call): call is string => call !== null);
  return [...new Set(calls)];
}

/** The DigitalOcean documentation URLs the rule cites. */
export function referencesForFinding(kind: string): readonly string[] {
  return RULE_INDEX.get(kind)?.references ?? [];
}
