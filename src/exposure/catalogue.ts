/**
 * The rule catalogue -- a human-readable index of everything the engine checks.
 *
 * This is what the exposures-page legend renders and what a reader scans to answer "what
 * does this tool actually look for?". It is kept honest by a test (`tests/exposure.test.ts`)
 * that asserts every registered rule kind has exactly one entry here and vice versa -- so a
 * new rule cannot ship without describing itself, and a deleted rule cannot linger.
 */

export interface RuleCatalogueEntry {
  kind: string;
  /** The family it belongs to, used to group the legend. */
  group: string;
  /** One line: what this rule flags. */
  title: string;
}

export const RULE_CATALOGUE: readonly RuleCatalogueEntry[] = [
  // Droplets & firewalls
  { kind: "droplet.no_firewall", group: "Droplets & firewalls", title: "Public droplet with no cloud firewall attached." },
  { kind: "droplet.public_ingress", group: "Droplets & firewalls", title: "Public droplet whose firewall admits the internet on one or more ports (after deny rules)." },

  // Load balancers
  { kind: "load_balancer.public_frontend", group: "Load balancers", title: "Load balancer with a public frontend (recorded; low unless a sensitive port is exposed)." },

  // Managed databases
  { kind: "database.public_no_trusted_sources", group: "Managed databases", title: "Database reachable from the internet with no trusted sources configured." },
  { kind: "database.trusted_source_is_public", group: "Managed databases", title: "Database whose trusted sources include the entire internet (0.0.0.0/0)." },
  { kind: "database.version_end_of_life", group: "Managed databases", title: "Database running an end-of-life, or soon end-of-life, engine version." },

  // Kubernetes
  { kind: "kubernetes.public_control_plane", group: "Kubernetes", title: "Cluster control plane reachable from any address." },
  { kind: "kubernetes.auto_upgrade_disabled", group: "Kubernetes", title: "Cluster not auto-applying patch upgrades (security patches wait for a human)." },
  { kind: "kubernetes.upgrade_available", group: "Kubernetes", title: "Cluster behind on available upgrades (patch upgrades flagged as security-relevant)." },

  // App Platform
  { kind: "app.public_ingress", group: "App Platform", title: "App with a public ingress URL (recorded for completeness)." },
  { kind: "app.plaintext_secret_env", group: "App Platform", title: "App storing credential-shaped variables in plaintext (GENERAL, not SECRET)." },

  // Certificates
  { kind: "certificate.expiring", group: "Certificates", title: "TLS certificate expired, expiring within 30 days, or in an error state (escalated if bound to a public LB)." },

  // Networking & DNS
  { kind: "netip.reserved_ip.unassigned", group: "Networking & DNS", title: "Reserved IP held by the account but attached to nothing (informational)." },
  { kind: "dns.record_points_to_unassigned_reserved_ip", group: "Networking & DNS", title: "DNS record pointing at the account's own unassigned reserved IP (stale-DNS heuristic)." },

  // Object storage
  { kind: "space.public_read", group: "Object storage", title: "Spaces bucket readable by anyone, proven by an anonymous request." },

  // Cross-resource attack paths
  { kind: "load_balancer.sensitive_backend_port", group: "Attack paths (cross-resource)", title: "Public load balancer forwarding to a sensitive backend port the backend firewall admits." },
  { kind: "path.public_workload_to_datastore", group: "Attack paths (cross-resource)", title: "Internet-exposed workload that a datastore trusts — compromise the workload, reach the data." },
  { kind: "path.exposed_app_leaks_datastore_credential", group: "Attack paths (cross-resource)", title: "Public app holding a datastore's credential in plaintext — the credential is exposed and the app is a pivot." },
];

const CATALOGUE_BY_KIND = new Map(RULE_CATALOGUE.map((entry) => [entry.kind, entry]));

/** The catalogue entry for a rule kind, or undefined if the kind is unknown. */
export function catalogueEntry(kind: string): RuleCatalogueEntry | undefined {
  return CATALOGUE_BY_KIND.get(kind);
}

/** Catalogue grouped for display, in first-seen group order. */
export function catalogueByGroup(): Array<{ group: string; entries: RuleCatalogueEntry[] }> {
  const order: string[] = [];
  const byGroup = new Map<string, RuleCatalogueEntry[]>();
  for (const entry of RULE_CATALOGUE) {
    if (!byGroup.has(entry.group)) {
      byGroup.set(entry.group, []);
      order.push(entry.group);
    }
    byGroup.get(entry.group)!.push(entry);
  }
  return order.map((group) => ({ group, entries: byGroup.get(group)! }));
}
