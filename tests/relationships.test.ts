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
