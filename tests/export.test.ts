import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/client";
import { FixtureDoHttp } from "../src/do/fixtures";
import { buildExport, NoAccountError } from "../src/export/build";
import { runSync } from "../src/sync/run";
import { createTestDb, fixedClock } from "./helpers/db";

/**
 * The export is the only compatibility requirement in the specification, so its shape
 * is asserted field by field rather than snapshotted.
 */

let db: Database;
let close: () => void;

beforeEach(() => {
  ({ db, close } = createTestDb());
});

afterEach(() => close());

describe("export shape", () => {
  it("matches the specified envelope", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const result = buildExport({ db, now: () => new Date("2026-02-01T12:00:00Z") });

    expect(result.schemaVersion).toBe("1");
    expect(result.generatedAt).toBe("2026-02-01T12:00:00.000Z");
    expect(result.account).toEqual({
      provider: "digitalocean",
      externalId: "team-1f4d2c9a",
      name: "Acme Platform",
    });
    expect(Object.keys(result).sort()).toEqual([
      "account",
      "coverage",
      "findings",
      "generatedAt",
      "relationships",
      "resources",
      "schemaVersion",
    ]);
  });

  it("emits resources in the normalized contract shape", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const { resources } = buildExport({ db });

    const droplet = resources.find((r) => r.externalId === "do:droplet:101");
    expect(Object.keys(droplet!).sort()).toEqual([
      "externalId",
      "isInternetExposed",
      "metadata",
      "name",
      "provider",
      "region",
      "resourceType",
      "sensitivity",
      "state",
      "tags",
    ]);

    expect(droplet!.provider).toBe("digitalocean");
    expect(droplet!.resourceType).toBe("digitalocean.droplet");
    expect(droplet!.isInternetExposed).toBe(true);
    expect(droplet!.tags).toEqual({ web: "", env: "production" });
  });

  it("names findings by fingerprint rather than id", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const { findings } = buildExport({ db });

    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(Object.keys(finding).sort()).toEqual([
        "evidence",
        "fingerprint",
        "kind",
        "remediation",
        "resourceExternalId",
        "severity",
        "summary",
        "title",
      ]);
      expect(finding.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("reports an unavailable collector as failed, with its reason preserved", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const { coverage } = buildExport({ db });

    // The schema has only two buckets, so `unavailable` maps into failed.
    const spaces = coverage.failedCollectors.find((c) => c.collector === "spaces");
    expect(spaces).toBeDefined();
    expect(spaces!.message).toMatch(/^unavailable: /);
    expect(spaces!.message).toMatch(/S3-compatible API/);
    expect(coverage.completedCollectors).toContain("droplets");
  });

  it("carries relationship evidence through unchanged", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const { relationships } = buildExport({ db });

    expect(relationships.length).toBeGreaterThan(0);
    for (const edge of relationships) {
      expect(["contains", "attached_to", "routes_to", "depends_on"]).toContain(edge.relationship);
      expect(["provider_reported", "derived"]).toContain(edge.evidence);
    }
  });
});

describe("export content safety", () => {
  it("contains no credential", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const serialised = JSON.stringify(buildExport({ db }));

    expect(serialised).not.toContain("REDACT-ME-fixture-password");
    expect(serialised).not.toContain("postgresql://");
    expect(serialised).not.toContain("doadmin");
    expect(serialised).not.toContain("dop_v1_");
  });
});

describe("export and resource lifecycle", () => {
  class WithoutLegacyDroplet extends FixtureDoHttp {
    override async get<T>(pathOrUrl: string): Promise<T> {
      const body = await super.get<T>(pathOrUrl);
      if (pathOrUrl === "/v2/droplets") {
        const typed = body as { droplets: Array<{ id: number }> };
        return { ...typed, droplets: typed.droplets.filter((d) => d.id !== 102) } as T;
      }
      return body;
    }
  }

  it("omits removed resources and resolved findings by default", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    expect(buildExport({ db }).resources.some((r) => r.externalId === "do:droplet:102")).toBe(true);

    clock.advance(60_000);
    await runSync({ http: new WithoutLegacyDroplet(), db, now: clock.now });

    const after = buildExport({ db });
    expect(after.resources.some((r) => r.externalId === "do:droplet:102")).toBe(false);
    expect(after.findings.some((f) => f.resourceExternalId === "do:droplet:102")).toBe(false);
  });

  it("can include removed history when asked", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    clock.advance(60_000);
    await runSync({ http: new WithoutLegacyDroplet(), db, now: clock.now });

    const withHistory = buildExport({ db, includeRemoved: true });
    expect(withHistory.resources.some((r) => r.externalId === "do:droplet:102")).toBe(true);
  });

  it("refuses to export before any sync has run", () => {
    expect(() => buildExport({ db })).toThrow(NoAccountError);
  });
});
