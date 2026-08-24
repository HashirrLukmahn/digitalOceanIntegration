import { describe, expect, it } from "vitest";
import {
  externalId,
  normalizeApp,
  normalizeDatabase,
  normalizeDroplet,
  normalizeKubernetes,
  normalizeLoadBalancer,
  normalizeRegistry,
  normalizeTags,
  normalizeVolume,
  TYPE_TABLE,
} from "../src/normalize/resource";
import type { DoDroplet } from "../src/do/types";

/**
 * The normalized contract is the integration boundary the evaluator reads, so the
 * identifiers and the sensitivity classification are pinned exactly.
 */

describe("externalId format", () => {
  it.each([
    ["project", 1234, "do:project:1234"],
    ["droplet", 3164444, "do:droplet:3164444"],
    ["firewall", "fb-uuid", "do:firewall:fb-uuid"],
    ["loadBalancer", "lb-uuid", "do:loadbalancer:lb-uuid"],
    ["vpc", "vpc-uuid", "do:vpc:vpc-uuid"],
    ["kubernetes", "k8s-uuid", "do:kubernetes:k8s-uuid"],
    ["database", "db-uuid", "do:dbaas:db-uuid"],
    ["space", "my-bucket", "do:space:my-bucket"],
    ["app", "app-uuid", "do:app:app-uuid"],
    ["registry", "my-registry", "do:registry:my-registry"],
    ["volume", "vol-uuid", "do:volume:vol-uuid"],
  ] as const)("builds %s ids as %s", (key, id, expected) => {
    expect(externalId(key, id)).toBe(expected);
  });

  it("uses DigitalOcean's own URN prefixes, which differ from the resource type", () => {
    // `loadbalancer` not `load_balancer`, `dbaas` not `database_cluster` -- these match
    // the URNs returned by the project-resources endpoint, so membership lines up.
    expect(TYPE_TABLE.loadBalancer.urn).toBe("loadbalancer");
    expect(TYPE_TABLE.loadBalancer.type).toBe("digitalocean.load_balancer");
    expect(TYPE_TABLE.database.urn).toBe("dbaas");
    expect(TYPE_TABLE.database.type).toBe("digitalocean.database_cluster");
  });
});

describe("sensitivity classification", () => {
  it("marks datastores", () => {
    expect(normalizeDatabase({ id: "d", name: "db" }).sensitivity).toBe("datastore");
    expect(normalizeVolume({ id: "v", name: "vol" }).sensitivity).toBe("datastore");
  });

  it("marks credential-bearing resources", () => {
    expect(normalizeKubernetes({ id: "k", name: "k8s" }).sensitivity).toBe("credential");
    expect(normalizeRegistry({ name: "reg" }).sensitivity).toBe("credential");
  });

  it("leaves ordinary compute and networking unclassified", () => {
    expect(normalizeDroplet({ id: 1, name: "web" }).sensitivity).toBe("none");
    expect(normalizeLoadBalancer({ id: "lb", name: "lb" }).sensitivity).toBe("none");
    expect(normalizeApp({ id: "a" }).sensitivity).toBe("none");
  });
});

describe("tag normalization", () => {
  it("splits key:value tags on the first colon", () => {
    expect(normalizeTags(["env:production", "team:platform"])).toEqual({
      env: "production",
      team: "platform",
    });
  });

  it("keeps a bare tag as a key with an empty value rather than inventing one", () => {
    expect(normalizeTags(["web"])).toEqual({ web: "" });
  });

  it("splits only on the first colon so the value keeps its own", () => {
    expect(normalizeTags(["url:https://example.com"])).toEqual({ url: "https://example.com" });
  });

  it("handles missing and empty tag lists", () => {
    expect(normalizeTags(undefined)).toEqual({});
    expect(normalizeTags([])).toEqual({});
  });
});

describe("droplet normalization", () => {
  const droplet: DoDroplet = {
    id: 3164444,
    name: "web-01",
    status: "active",
    region: { slug: "nyc3", name: "New York 3" },
    size_slug: "s-1vcpu-1gb",
    vpc_uuid: "vpc-1",
    tags: ["env:prod"],
    networks: {
      v4: [
        { ip_address: "104.236.32.182", type: "public" },
        { ip_address: "10.128.0.5", type: "private" },
      ],
      v6: [{ ip_address: "2604:a880::1", type: "public" }],
    },
  };

  it("separates public from private addresses", () => {
    const resource = normalizeDroplet(droplet);
    expect(resource.metadata.public_ipv4).toEqual(["104.236.32.182"]);
    expect(resource.metadata.private_ipv4).toEqual(["10.128.0.5"]);
    expect(resource.metadata.public_ipv6).toEqual(["2604:a880::1"]);
  });

  it("maps region slug and provider state", () => {
    const resource = normalizeDroplet(droplet);
    expect(resource.region).toBe("nyc3");
    expect(resource.state).toBe("active");
  });

  it("never decides exposure during normalization", () => {
    // Exposure is the exposure engine's job, deterministically, with evidence.
    expect(normalizeDroplet(droplet).isInternetExposed).toBe(false);
  });

  it("tolerates a droplet with no networks, region, or tags", () => {
    const resource = normalizeDroplet({ id: 1, name: "bare" });
    expect(resource.region).toBeNull();
    expect(resource.state).toBeNull();
    expect(resource.tags).toEqual({});
    expect(resource.metadata.public_ipv4).toBeUndefined();
  });

  it("omits empty address arrays instead of storing []", () => {
    const resource = normalizeDroplet({
      id: 2,
      name: "private-only",
      networks: { v4: [{ ip_address: "10.0.0.1", type: "private" }] },
    });
    expect("public_ipv4" in resource.metadata).toBe(false);
    expect(resource.metadata.private_ipv4).toEqual(["10.0.0.1"]);
  });
});

describe("app normalization", () => {
  it("prefers the spec name over the raw id", () => {
    expect(normalizeApp({ id: "abc", spec: { name: "storefront" } }).name).toBe("storefront");
  });

  it("falls back to the id when the spec has no name", () => {
    expect(normalizeApp({ id: "abc" }).name).toBe("abc");
  });
});
