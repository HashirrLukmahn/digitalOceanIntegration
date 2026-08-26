import type { RawInventory } from "../do/collectors";
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

export type RelationshipKind = "contains" | "attached_to" | "routes_to" | "depends_on";
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

  return dedupe(edges);
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
