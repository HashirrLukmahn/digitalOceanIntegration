import { describe, expect, it } from "vitest";
import {
  CollectorUnavailableError,
  createSpacesCollector,
  emptyInventory,
  type RawInventory,
} from "../src/do/collectors";
import { FixtureDoHttp } from "../src/do/fixtures";
import type { DoHttp } from "../src/do/http";
import { cloudRelationships, cloudResources, exposureFindings } from "../src/db/schema";
import { runSync } from "../src/sync/run";
import { createTestDb } from "./helpers/db";
import {
  bucketEndpoint,
  loadSpacesConfig,
  parseSpacesBuckets,
  probeBucket,
  spacesMode,
  verifySpacesKey,
  type Fetcher,
} from "../src/do/spaces";
import { evaluateExposure } from "../src/exposure/engine";
import { spacePublicReadRule } from "../src/exposure/rules/space";
import { buildContext } from "../src/exposure/types";

/**
 * Spaces is opt-in and bucket-scoped. The tests that matter most are the refusals:
 * an over-privileged key must be rejected rather than used, and an absent
 * configuration must produce an honest "not assessed" rather than a silent pass.
 */

const keysHttp = (keys: Array<{ access_key: string; grants: unknown[] }>): DoHttp => ({
  async get<T>(): Promise<T> {
    return { keys } as T;
  },
});

const fetcherReturning = (status: number): Fetcher => async () => ({
  status,
  text: async () => "",
});

describe("configuration parsing", () => {
  it("parses region-qualified buckets", () => {
    expect(parseSpacesBuckets("nyc3/assets,ams3/backups")).toEqual([
      { region: "nyc3", name: "assets" },
      { region: "ams3", name: "backups" },
    ]);
  });

  it("tolerates whitespace and empty entries", () => {
    expect(parseSpacesBuckets(" nyc3/assets , ")).toEqual([{ region: "nyc3", name: "assets" }]);
  });

  it("returns nothing when unset", () => {
    expect(parseSpacesBuckets(undefined)).toEqual([]);
    expect(parseSpacesBuckets("")).toEqual([]);
  });

  it.each(["assets", "nyc3/", "/assets"])("rejects the unqualified entry %s", (entry) => {
    // A bucket lives in exactly one region, and Spaces endpoints are regional.
    // Guessing the region would mean probing the wrong host and reporting nothing.
    expect(() => parseSpacesBuckets(entry)).toThrow(/region\/bucket/);
  });

  it("builds the regional endpoint", () => {
    expect(bucketEndpoint({ region: "nyc3", name: "assets" })).toBe(
      "https://assets.nyc3.digitaloceanspaces.com",
    );
  });

  it("derives the mode from what is configured", () => {
    expect(spacesMode({ buckets: [] })).toBe("unavailable");
    expect(spacesMode({ buckets: [{ region: "nyc3", name: "a" }] })).toBe("probe_only");
    expect(
      spacesMode({
        buckets: [{ region: "nyc3", name: "a" }],
        accessKeyId: "k",
        secretAccessKey: "s",
      }),
    ).toBe("authenticated");
  });

  it("reads configuration from the environment", () => {
    const config = loadSpacesConfig({
      SPACES_BUCKETS: "nyc3/assets",
      SPACES_ACCESS_KEY_ID: "AKID",
      SPACES_SECRET_ACCESS_KEY: "SECRET",
    } as unknown as NodeJS.ProcessEnv);
    expect(config.buckets).toHaveLength(1);
    expect(config.accessKeyId).toBe("AKID");
  });
});

describe("least-privilege enforcement", () => {
  it("accepts a key granting read on named buckets", async () => {
    const result = await verifySpacesKey(
      keysHttp([
        {
          access_key: "AKID",
          grants: [
            { bucket: "assets", permission: "read" },
            { bucket: "backups", permission: "read" },
          ],
        },
      ]),
      "AKID",
    );
    expect(result.ok).toBe(true);
    expect(result.grantedBuckets).toEqual(["assets", "backups"]);
  });

  it("refuses an account-wide key", async () => {
    // Empty bucket means all buckets. This is the credential we must never hold.
    const result = await verifySpacesKey(
      keysHttp([{ access_key: "AKID", grants: [{ bucket: "", permission: "fullaccess" }] }]),
      "AKID",
    );
    expect(result.ok).toBe(false);
    expect(result.problems.join(" ")).toMatch(/all buckets/i);
  });

  it("refuses a key that can write or delete", async () => {
    const result = await verifySpacesKey(
      keysHttp([{ access_key: "AKID", grants: [{ bucket: "assets", permission: "readwrite" }] }]),
      "AKID",
    );
    expect(result.ok).toBe(false);
    expect(result.problems.join(" ")).toMatch(/more than reading/i);
  });

  it("refuses a key with no grants", async () => {
    const result = await verifySpacesKey(keysHttp([{ access_key: "AKID", grants: [] }]), "AKID");
    expect(result.ok).toBe(false);
  });

  it("reports clearly when the key cannot be found or checked", async () => {
    const result = await verifySpacesKey(keysHttp([]), "AKID");
    expect(result.ok).toBe(false);
    expect(result.problems.join(" ")).toMatch(/does not exist|spaces_key:read/);
  });
});

describe("anonymous public-read probe", () => {
  it("treats a 200 as proof the bucket is publicly listable", async () => {
    const probe = await probeBucket({ region: "nyc3", name: "leaky" }, fetcherReturning(200));
    expect(probe.publiclyListable).toBe(true);
    expect(probe.status).toBe(200);
  });

  it.each([403, 401, 404])("treats %d as not publicly listable", async (status) => {
    const probe = await probeBucket({ region: "nyc3", name: "private" }, fetcherReturning(status));
    expect(probe.publiclyListable).toBe(false);
  });

  it("records a network failure without claiming the bucket is safe", async () => {
    const probe = await probeBucket({ region: "nyc3", name: "x" }, async () => {
      throw new Error("ENOTFOUND");
    });
    expect(probe.publiclyListable).toBe(false);
    expect(probe.status).toBeNull();
    expect(probe.error).toContain("ENOTFOUND");
  });
});

describe("collector behaviour", () => {
  const run = async (collector: ReturnType<typeof createSpacesCollector>, http: DoHttp) => {
    const inventory: RawInventory = emptyInventory();
    await collector.run(http, inventory);
    return inventory;
  };

  it("declares itself unavailable when no buckets are configured", async () => {
    const collector = createSpacesCollector({ config: { buckets: [] } });
    await expect(run(collector, keysHttp([]))).rejects.toThrow(CollectorUnavailableError);
    await expect(run(collector, keysHttp([]))).rejects.toThrow(/SPACES_BUCKETS/);
  });

  it("probes without any credential when only buckets are configured", async () => {
    const collector = createSpacesCollector({
      config: { buckets: [{ region: "nyc3", name: "leaky" }] },
      fetcher: fetcherReturning(200),
    });
    const inventory = await run(collector, keysHttp([]));

    expect(inventory.spacesMode).toBe("probe_only");
    expect(inventory.spaces[0]!.publiclyListable).toBe(true);
  });

  it("refuses to run at all when handed an over-privileged key", async () => {
    // The credential is rejected, not merely warned about.
    const collector = createSpacesCollector({
      config: {
        buckets: [{ region: "nyc3", name: "assets" }],
        accessKeyId: "AKID",
        secretAccessKey: "S",
      },
      fetcher: fetcherReturning(200),
    });
    const http = keysHttp([
      { access_key: "AKID", grants: [{ bucket: "", permission: "fullaccess" }] },
    ]);

    await expect(run(collector, http)).rejects.toThrow(CollectorUnavailableError);
    await expect(run(collector, http)).rejects.toThrow(/refused/i);
  });

  it("narrows the scan to buckets the key was actually granted", async () => {
    // Configuration claims two buckets; the key only covers one. DigitalOcean's
    // grants win, because a bucket the key cannot read cannot be assessed.
    const collector = createSpacesCollector({
      config: {
        buckets: [
          { region: "nyc3", name: "assets" },
          { region: "nyc3", name: "not-granted" },
        ],
        accessKeyId: "AKID",
        secretAccessKey: "S",
      },
      fetcher: fetcherReturning(403),
    });
    const inventory = await run(
      collector,
      keysHttp([{ access_key: "AKID", grants: [{ bucket: "assets", permission: "read" }] }]),
    );

    expect(inventory.spaces.map((p) => p.bucket.name)).toEqual(["assets"]);
  });
});

describe("rule: publicly readable bucket", () => {
  const withProbes = (probes: RawInventory["spaces"]): RawInventory => ({
    ...emptyInventory(),
    spaces: probes,
  });

  it("fires critical for a publicly listable bucket", () => {
    const findings = spacePublicReadRule.evaluate(
      buildContext(
        withProbes([
          {
            bucket: { region: "nyc3", name: "leaky" },
            endpoint: "https://leaky.nyc3.digitaloceanspaces.com",
            publiclyListable: true,
            status: 200,
          },
        ]),
      ),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.evidence.method).toBe("unauthenticated HTTP GET");
  });

  it("does not fire for a restricted bucket", () => {
    const findings = spacePublicReadRule.evaluate(
      buildContext(
        withProbes([
          {
            bucket: { region: "nyc3", name: "private" },
            endpoint: "https://private.nyc3.digitaloceanspaces.com",
            publiclyListable: false,
            status: 403,
          },
        ]),
      ),
    );
    expect(findings).toHaveLength(0);
  });

  it("marks the bucket internet-exposed and classifies it as a datastore", () => {
    const result = evaluateExposure(
      "acct",
      withProbes([
        {
          bucket: { region: "nyc3", name: "leaky" },
          endpoint: "https://leaky.nyc3.digitaloceanspaces.com",
          publiclyListable: true,
          status: 200,
        },
      ]),
    );
    expect(result.exposedResourceIds.has("do:space:leaky")).toBe(true);
  });
});

/**
 * Sample-data mode has to be genuinely offline.
 *
 * Spaces is the one collector that cannot swap transport through `DoHttp`: detecting a
 * public bucket is an anonymous request straight to the S3-compatible endpoint, which
 * has no v2 equivalent to record. Before this was wired up, `DATA_SOURCE=fixtures`
 * with `SPACES_BUCKETS` still set produced a hybrid run -- recorded inventory, real
 * buckets probed over the internet -- and reported it as complete coverage.
 */
describe("spaces in sample-data mode", () => {
  const withFixtureMode = async <T,>(body: () => Promise<T>): Promise<T> => {
    const before = { ds: process.env.DATA_SOURCE, buckets: process.env.SPACES_BUCKETS };
    const realFetch = globalThis.fetch;
    process.env.DATA_SOURCE = "fixtures";
    // Deliberately left pointing at real buckets: the mode must win over the config.
    process.env.SPACES_BUCKETS = "sfo1/some-real-bucket";
    globalThis.fetch = (async (input: unknown) => {
      throw new Error(`sample-data mode reached the network: ${String(input)}`);
    }) as typeof fetch;

    try {
      return await body();
    } finally {
      globalThis.fetch = realFetch;
      process.env.DATA_SOURCE = before.ds;
      process.env.SPACES_BUCKETS = before.buckets;
      if (before.ds === undefined) delete process.env.DATA_SOURCE;
      if (before.buckets === undefined) delete process.env.SPACES_BUCKETS;
    }
  };

  it("uses recorded buckets and never touches the network", async () => {
    const result = await withFixtureMode(async () => {
      const { db, close } = createTestDb();
      const run = await runSync({ http: new FixtureDoHttp(), db });
      const spaces = db
        .select()
        .from(cloudResources)
        .all()
        .filter((r) => r.resourceType === "digitalocean.space");
      close();
      return { run, spaces };
    });

    // The env named one live bucket; the recorded pair is what came back.
    expect(result.spaces.map((s) => s.externalId).sort()).toEqual([
      "do:space:acme-backups",
      "do:space:acme-public-assets",
    ]);
    expect(result.run.coverage.unavailableCollectors).toEqual([]);
    expect(result.run.status).toBe("completed");
  });

  it("carries a public bucket and its true negative, and links both to the project", async () => {
    const { findings, edges } = await withFixtureMode(async () => {
      const { db, close } = createTestDb();
      await runSync({ http: new FixtureDoHttp(), db });
      const findings = db
        .select()
        .from(exposureFindings)
        .all()
        .filter((f) => f.kind.startsWith("space."));
      const edges = db
        .select()
        .from(cloudRelationships)
        .all()
        .filter((e) => e.targetExternalId.startsWith("do:space:"));
      close();
      return { findings, edges };
    });

    // Exactly one of the two buckets is public, so the corpus proves the rule fires
    // and that it stays silent on the restricted one.
    expect(findings).toHaveLength(1);
    expect(findings[0]!.resourceExternalId).toBe("do:space:acme-public-assets");
    expect(findings[0]!.severity).toBe("critical");

    // Regression: Spaces were missing from the derivation's known-resource set, so
    // these edges were silently dropped despite the bucket being inventoried.
    expect(edges.map((e) => e.targetExternalId).sort()).toEqual([
      "do:space:acme-backups",
      "do:space:acme-public-assets",
    ]);
    expect(edges.every((e) => e.relationship === "contains")).toBe(true);
  });
});
