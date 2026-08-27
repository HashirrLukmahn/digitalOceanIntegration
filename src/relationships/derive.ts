import type { RawInventory } from "../do/collectors";
import { isPublicInternetCidr } from "../exposure/ports";
import { externalId } from "../normalize/resource";

/**
 * Resource relationships.
 *
 * Two constraints from the specification shape this module:
 *
 *   1. "Do not infer access or privilege-escalation relationships from DigitalOcean
 *      team membership." Nothing here reads team data.
 *   2. "A missing relationship is better than an unsupported security claim." Every
 *      edge below is either something DigitalOcean explicitly reports, or a
 *      deterministic consequence of two provider-reported facts -- and which of the
 *      two it is gets recorded in `evidence`, so a reader can weigh it.
 */

export type RelationshipKind = "contains" | "attached_to" | "routes_to" | "depends_on" | "trusts";
export type EvidenceSource = "provider_reported" | "derived";

export interface DerivedRelationship {
  sourceExternalId: string;
  targetExternalId: string;
  relationship: RelationshipKind;
  evidence: EvidenceSource;
  metadata: Record<string, unknown>;
}

export function deriveRelationships(inventory: RawInventory): DerivedRelationship[] {
  const edges: DerivedRelationship[] = [];

  // Every external id we actually collected, so membership URNs pointing at resource
  // types we do not inventory (images, snapshots) are dropped rather than dangling.
  const known = new Set<string>([
    ...inventory.projects.map((p) => externalId("project", p.id)),
    ...inventory.droplets.map((d) => externalId("droplet", d.id)),
    ...inventory.firewalls.map((f) => externalId("firewall", f.id)),
    ...inventory.loadBalancers.map((lb) => externalId("loadBalancer", lb.id)),
    ...inventory.vpcs.map((v) => externalId("vpc", v.id)),
    ...inventory.databases.map((db) => externalId("database", db.id)),
    ...inventory.kubernetes.map((k) => externalId("kubernetes", k.id)),
    ...inventory.apps.map((a) => externalId("app", a.id)),
    ...inventory.volumes.map((v) => externalId("volume", v.id)),
    ...inventory.registries.map((r) => externalId("registry", r.name)),
    // Spaces are keyed by bucket name, which is exactly what the project URN carries.
    // Omitting them here silently dropped every project->space edge: the bucket was
    // inventoried, the membership was reported, and the edge vanished as "dangling".
    ...inventory.spaces.map((s) => externalId("space", s.bucket.name)),
  ]);

  // --- Project contains resource -------------------------------------------------
  // DigitalOcean reports membership as URNs already in `do:<type>:<id>` form, which is
  // the same identifier scheme used throughout, so no translation is needed.
  for (const { projectId, urns } of inventory.projectResources) {
    const source = externalId("project", projectId);
    for (const urn of urns) {
      if (!known.has(urn)) continue;
      edges.push({
        sourceExternalId: source,
        targetExternalId: urn,
        relationship: "contains",
        evidence: "provider_reported",
        metadata: { via: "/v2/projects/{id}/resources" },
      });
    }
  }

  // --- Firewall attached_to droplet ----------------------------------------------
  for (const firewall of inventory.firewalls) {
    const source = externalId("firewall", firewall.id);

    for (const dropletId of firewall.droplet_ids ?? []) {
      const target = externalId("droplet", dropletId);
      if (!known.has(target)) continue;
      edges.push({
        sourceExternalId: source,
        targetExternalId: target,
        relationship: "attached_to",
        evidence: "provider_reported",
        metadata: { via: "firewall.droplet_ids" },
      });
    }

    // Tag-based attachment is a genuine DigitalOcean mechanism, but the association is
    // computed by us from two reported facts, so it is marked `derived`.
    const firewallTags = new Set(firewall.tags ?? []);
    if (firewallTags.size > 0) {
      for (const droplet of inventory.droplets) {
        const matched = (droplet.tags ?? []).filter((tag) => firewallTags.has(tag));
        if (matched.length === 0) continue;
        if ((firewall.droplet_ids ?? []).includes(droplet.id)) continue; // already direct
        edges.push({
          sourceExternalId: source,
          targetExternalId: externalId("droplet", droplet.id),
          relationship: "attached_to",
          evidence: "derived",
          metadata: { via: "shared tag", tags: matched },
        });
      }
    }
  }

  // --- Droplet attached_to VPC ---------------------------------------------------
  for (const droplet of inventory.droplets) {
    if (!droplet.vpc_uuid) continue;
    const target = externalId("vpc", droplet.vpc_uuid);
    if (!known.has(target)) continue;
    edges.push({
      sourceExternalId: externalId("droplet", droplet.id),
      targetExternalId: target,
      relationship: "attached_to",
      evidence: "provider_reported",
      metadata: { via: "droplet.vpc_uuid" },
    });
  }

  // --- Load balancer routes_to droplet -------------------------------------------
  for (const lb of inventory.loadBalancers) {
    const source = externalId("loadBalancer", lb.id);

    for (const dropletId of lb.droplet_ids ?? []) {
      const target = externalId("droplet", dropletId);
      if (!known.has(target)) continue;
      edges.push({
        sourceExternalId: source,
        targetExternalId: target,
        relationship: "routes_to",
        evidence: "provider_reported",
        metadata: { via: "load_balancer.droplet_ids" },
      });
    }

    // A tag-based load balancer selects its backends dynamically.
    if (lb.tag) {
      for (const droplet of inventory.droplets) {
        if (!(droplet.tags ?? []).includes(lb.tag)) continue;
        if ((lb.droplet_ids ?? []).includes(droplet.id)) continue;
        edges.push({
          sourceExternalId: source,
          targetExternalId: externalId("droplet", droplet.id),
          relationship: "routes_to",
          evidence: "derived",
          metadata: { via: "load_balancer.tag", tag: lb.tag },
        });
      }
    }
  }

  // --- Volume attached_to droplet ------------------------------------------------
  for (const volume of inventory.volumes) {
    for (const dropletId of volume.droplet_ids ?? []) {
      const target = externalId("droplet", dropletId);
      if (!known.has(target)) continue;
      edges.push({
        sourceExternalId: externalId("volume", volume.id),
        targetExternalId: target,
        relationship: "attached_to",
        evidence: "provider_reported",
        metadata: { via: "volume.droplet_ids" },
      });
    }
  }

  // --- App depends_on database ---------------------------------------------------
  // Only when the app spec names a cluster we actually collected. App Platform can
  // also attach dev databases that have no cluster of their own; those name nothing
  // resolvable and are skipped rather than guessed at.
  const databasesByName = new Map(inventory.databases.map((db) => [db.name, db]));
  for (const app of inventory.apps) {
    for (const spec of app.spec?.databases ?? []) {
      const clusterName = spec.cluster_name;
      if (!clusterName) continue;
      const cluster = databasesByName.get(clusterName);
      if (!cluster) continue;
      edges.push({
        sourceExternalId: externalId("app", app.id),
        targetExternalId: externalId("database", cluster.id),
        relationship: "depends_on",
        evidence: "derived",
        metadata: { via: "app.spec.databases[].cluster_name", clusterName, engine: spec.engine ?? null },
      });
    }
  }

  // --- Database trusts source ----------------------------------------------------
  // Trusted sources are the ONE place the database's own firewall names other resources,
  // so this is the edge the attack-path rules and the graph read as "a compromised
  // workload can reach this datastore". Direction is truster -> trusted: the cluster is
  // the source, the workload it admits is the target.
  //
  // Provenance splits cleanly. A droplet/k8s/app trusted source names a concrete resource
  // id DigitalOcean returned verbatim -> provider_reported. A tag or an IP/CIDR has to be
  // *resolved* to the concrete resources it currently matches, and that membership can
  // change between syncs, so the resolution is an inference -> derived. The trust *form*
  // and the raw matched value are recorded in `metadata`, never in the enum-valued
  // `evidence` field.
  //
  // VPC membership is deliberately never a trust edge: DigitalOcean has no "vpc"
  // trusted-source type, so claiming one would be unfalsifiable. An IP/CIDR that resolves
  // to no collected resource yields no edge -- it is an external address with no node to
  // point at, and a wide-open 0.0.0.0/0 is already reported as a finding.
  // Both v4 and v6 addresses: a database may name a droplet's IPv6 address as a trusted
  // source, and missing that path would silently drop a real attack pivot. Exact-IP
  // matching works for either family; CIDR matching below resolves IPv4 ranges only (an
  // IPv6 CIDR simply matches nothing rather than matching wrongly).
  const dropletAddresses = inventory.droplets.map((droplet) => ({
    externalId: externalId("droplet", droplet.id),
    addresses: [
      ...(droplet.networks?.v4 ?? []).map((n) => n.ip_address),
      ...(droplet.networks?.v6 ?? []).map((n) => n.ip_address),
    ].filter((ip): ip is string => Boolean(ip)),
  }));

  for (const cluster of inventory.databases) {
    const rules = inventory.databaseFirewalls[cluster.id];
    if (rules === undefined) continue; // firewall fetch failed for this cluster; say nothing
    const source = externalId("database", cluster.id);

    for (const rule of rules) {
      switch (rule.type) {
        case "droplet":
        case "k8s":
        case "app": {
          // A trusted source names a concrete resource id verbatim. `k8s` is DigitalOcean's
          // trusted-source label for what we inventory as `kubernetes`.
          const targetKey = rule.type === "k8s" ? "kubernetes" : rule.type;
          const target = externalId(targetKey, rule.value);
          if (!known.has(target)) continue;
          edges.push({
            sourceExternalId: source,
            targetExternalId: target,
            relationship: "trusts",
            evidence: "provider_reported",
            metadata: { via: "database_firewall.trusted_source", form: rule.type, value: rule.value },
          });
          break;
        }
        case "tag": {
          // Any droplet carrying the tag is admitted. Resolution -> derived.
          for (const droplet of inventory.droplets) {
            if (!(droplet.tags ?? []).includes(rule.value)) continue;
            edges.push({
              sourceExternalId: source,
              targetExternalId: externalId("droplet", droplet.id),
              relationship: "trusts",
              evidence: "derived",
              metadata: { via: "database_firewall.trusted_source", form: "tag", value: rule.value },
            });
          }
          break;
        }
        case "ip_addr": {
          const value = rule.value.trim();
          // A whole-internet source is a public-exposure finding, not a scoped trust edge;
          // resolving it would falsely "trust" every droplet in the account.
          if (isPublicInternetCidr(value)) break;
          const isCidr = value.includes("/");
          for (const droplet of dropletAddresses) {
            const matched = droplet.addresses.some((addr) =>
              isCidr ? ipv4InCidr(addr, value) : addr === value,
            );
            if (!matched) continue;
            edges.push({
              sourceExternalId: source,
              targetExternalId: droplet.externalId,
              relationship: "trusts",
              evidence: "derived",
              metadata: {
                via: "database_firewall.trusted_source",
                form: isCidr ? "cidr" : "ip",
                value,
              },
            });
          }
          break;
        }
        default:
          break; // unknown trusted-source type: record nothing rather than guess
      }
    }
  }

  return dedupe(edges);
}

/** Parse a dotted-quad IPv4 address to an unsigned 32-bit integer, or null if malformed. */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** Whether an IPv4 address falls inside an IPv4 CIDR block. IPv6 is not resolved. */
function ipv4InCidr(ip: string, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base ?? "");
  if (ipInt === null || baseInt === null) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/**
 * The table has a uniqueness constraint on (account, source, target, relationship),
 * so collapse duplicates here rather than letting an insert fail. A provider-reported
 * edge always wins over a derived one describing the same association.
 */
function dedupe(edges: readonly DerivedRelationship[]): DerivedRelationship[] {
  const byKey = new Map<string, DerivedRelationship>();

  for (const edge of edges) {
    const key = `${edge.sourceExternalId}|${edge.targetExternalId}|${edge.relationship}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, edge);
      continue;
    }
    if (existing.evidence === "derived" && edge.evidence === "provider_reported") {
      byKey.set(key, edge);
    }
  }

  return [...byKey.values()];
}
