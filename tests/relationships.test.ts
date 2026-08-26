import { describe, expect, it } from "vitest";
import { emptyInventory } from "../src/do/collectors";
import { deriveRelationships } from "../src/relationships/derive";

/**
 * Project membership is dropped for URNs pointing at resource types we do not
 * inventory, so that a `contains` edge never dangles. The hazard is the inverse: a
 * type we *do* inventory but forget to add to that set disappears from the graph
 * while still appearing in the resource list, which reads as "the provider never
 * reported it" rather than "we lost it".
 */
describe("project contains", () => {
  const inventoryWithSpace = () => {
    const inv = emptyInventory();
    inv.projects = [{ id: "p1", name: "first-project" }] as never;
    inv.projectResources = [
      { projectId: "p1", urns: ["do:space:cold-bucket-1", "do:snapshot:not-collected"] },
    ];
    inv.spaces = [
      {
        bucket: { region: "sfo1", name: "cold-bucket-1" },
        endpoint: "https://cold-bucket-1.sfo1.digitaloceanspaces.com",
        publiclyListable: false,
        status: 403,
      },
    ];
    return inv;
  };

  it("links a project to a Space it reports owning", () => {
    const edges = deriveRelationships(inventoryWithSpace());
    const contains = edges.filter((e) => e.relationship === "contains");

    expect(contains).toHaveLength(1);
    expect(contains[0]!.targetExternalId).toBe("do:space:cold-bucket-1");
    expect(contains[0]!.evidence).toBe("provider_reported");
  });

  it("still drops membership URNs for types that were never collected", () => {
    const edges = deriveRelationships(inventoryWithSpace());
    expect(edges.map((e) => e.targetExternalId)).not.toContain("do:snapshot:not-collected");
  });
});

/**
 * The `trusts` edge is the one place a datastore's own firewall names other resources,
 * so its provenance has to be exactly right: a directly-named resource is
 * provider-reported, while a tag or CIDR that had to be resolved to concrete resources is
 * derived, and the trust *form* lives in metadata, never in the enum-valued evidence field.
 */
describe("database trusts", () => {
  const withCluster = (rules: Array<{ type: string; value: string }>, over: Record<string, unknown> = {}) => {
    const inv = emptyInventory();
    inv.databases = [{ id: "db-1", name: "pg" }] as never;
    inv.databaseFirewalls = { "db-1": rules as never };
    inv.droplets = [
      {
        id: 101,
        name: "api",
        tags: ["backend"],
        networks: {
          v4: [
            { ip_address: "203.0.113.9", type: "public" },
            { ip_address: "10.10.0.4", type: "private" },
          ],
        },
      },
    ] as never;
    Object.assign(inv, over);
    return inv;
  };

  const trustEdges = (inv: ReturnType<typeof withCluster>) =>
    deriveRelationships(inv).filter((e) => e.relationship === "trusts");

  it("marks a directly-named droplet trusted source as provider_reported", () => {
    const edges = trustEdges(withCluster([{ type: "droplet", value: "101" }]));
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({
      sourceExternalId: "do:dbaas:db-1",
      targetExternalId: "do:droplet:101",
      relationship: "trusts",
      evidence: "provider_reported",
    });
    expect(edges[0]!.metadata).toMatchObject({ form: "droplet", value: "101" });
  });

  it("resolves a tag trusted source to matching droplets as derived", () => {
    const edges = trustEdges(withCluster([{ type: "tag", value: "backend" }]));
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ targetExternalId: "do:droplet:101", evidence: "derived" });
    expect(edges[0]!.metadata).toMatchObject({ form: "tag", value: "backend" });
  });

  it("resolves an exact-IP trusted source against a droplet's private address", () => {
    const edges = trustEdges(withCluster([{ type: "ip_addr", value: "10.10.0.4" }]));
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ targetExternalId: "do:droplet:101", evidence: "derived" });
    expect(edges[0]!.metadata).toMatchObject({ form: "ip", value: "10.10.0.4" });
  });

  it("resolves a CIDR trusted source that contains a droplet address", () => {
    const edges = trustEdges(withCluster([{ type: "ip_addr", value: "10.10.0.0/24" }]));
    expect(edges).toHaveLength(1);
    expect(edges[0]!.metadata).toMatchObject({ form: "cidr", value: "10.10.0.0/24" });
  });

  it("emits no edge for an external address that matches no collected resource", () => {
    // A 0.0.0.0/0 trusted source is a finding, not a resource-to-resource edge.
    expect(trustEdges(withCluster([{ type: "ip_addr", value: "0.0.0.0/0" }]))).toHaveLength(0);
    expect(trustEdges(withCluster([{ type: "ip_addr", value: "198.51.100.7" }]))).toHaveLength(0);
  });

  it("stays silent when the cluster's firewall was never fetched", () => {
    const inv = withCluster([]);
    inv.databaseFirewalls = {}; // fetch failed -> cluster absent, unknown not empty
    expect(trustEdges(inv)).toHaveLength(0);
  });

  it("never claims VPC-wide trust", () => {
    // There is no "vpc" trusted-source type; a vpc value is an unknown type and yields nothing.
    expect(trustEdges(withCluster([{ type: "vpc", value: "vpc-abc" }]))).toHaveLength(0);
  });
});
