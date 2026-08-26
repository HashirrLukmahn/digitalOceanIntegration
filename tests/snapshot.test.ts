import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Database } from "../src/db/client";
import { snapshots } from "../src/db/schema";
import { FixtureDoHttp } from "../src/do/fixtures";
import type { QueryParams } from "../src/do/http";
import { runSync } from "../src/sync/run";
import {
  assembleSnapshotDocument,
  edgeCoverageKeys,
  SNAPSHOT_VERSION,
  type SnapshotInputResource,
} from "../src/snapshot/document";
import { createTestDb, fixedClock } from "./helpers/db";

/**
 * The snapshot is an internal, post-reconciliation, per-item-fresh evaluated-output
 * document. Its purity is tested directly; its atomic write and merged-view semantics are
 * tested through a real sync.
 */

const resource = (over: Partial<SnapshotInputResource> & { externalId: string; lastSeenAt: Date }): SnapshotInputResource => ({
  provider: "digitalocean",
  resourceType: "digitalocean.droplet",
  name: "r",
  region: null,
  state: null,
  isInternetExposed: false,
  sensitivity: "none",
  tags: {},
  metadata: {},
  ...over,
});

describe("assembleSnapshotDocument", () => {
  const seenAt = new Date("2026-01-02T00:00:00.000Z");
  const earlier = new Date("2026-01-01T00:00:00.000Z");
  const authoritativeKeys = new Set([
    "digitalocean.droplet",
    "digitalocean.database_cluster",
    "database_firewall:db-1",
  ]);

  const build = () =>
    assembleSnapshotDocument({
      syncRunId: "run-1",
      status: "partial",
      coverage: { completedCollectors: [], failedCollectors: [], unavailableCollectors: [] },
      seenAt,
      generatedAt: seenAt.toISOString(),
      authoritativeKeys,
      resources: [
        resource({ externalId: "do:droplet:101", lastSeenAt: seenAt }),
        resource({ externalId: "do:droplet:102", lastSeenAt: earlier }),
      ],
      relationships: [
        {
          sourceExternalId: "do:dbaas:db-1",
          targetExternalId: "do:droplet:101",
          relationship: "trusts",
          evidence: "provider_reported",
          metadata: { form: "droplet" },
        },
        {
          // A space's dataset is not authoritative this run -> this edge is stale.
          sourceExternalId: "do:project:p1",
          targetExternalId: "do:space:cold",
          relationship: "contains",
          evidence: "provider_reported",
          metadata: {},
        },
      ],
      findings: [],
    });

  it("versions itself distinctly from the export and is self-describing", () => {
    const doc = build();
    expect(doc.snapshotVersion).toBe(SNAPSHOT_VERSION);
    expect(doc.syncRunId).toBe("run-1");
    expect(doc.status).toBe("partial");
  });

  it("marks each resource observed or retained by whether it was written this run", () => {
    const doc = build();
    const byId = Object.fromEntries(doc.resources.map((r) => [r.externalId, r.freshness]));
    expect(byId["do:droplet:101"]).toBe("observed");
    expect(byId["do:droplet:102"]).toBe("retained");
  });

  it("carries the internal trusts edge with its multi-dataset coverage keys", () => {
    const doc = build();
    const trust = doc.relationships.find((e) => e.relationship === "trusts")!;
    expect(trust.coverageKeys).toEqual(
      expect.arrayContaining(["digitalocean.database_cluster", "digitalocean.droplet", "database_firewall:db-1"]),
    );
    expect(trust.freshness).toBe("observed");
  });

  it("marks an edge retained when one of its datasets was not authoritative", () => {
    const doc = build();
    const contains = doc.relationships.find((e) => e.relationship === "contains")!;
    expect(contains.freshness).toBe("retained");
  });

  it("adds a database_firewall child key only to trust edges", () => {
    expect(
      edgeCoverageKeys({
        sourceExternalId: "do:dbaas:db-9",
        targetExternalId: "do:droplet:5",
        relationship: "trusts",
        evidence: "provider_reported",
        metadata: {},
      }),
    ).toContain("database_firewall:db-9");
    expect(
      edgeCoverageKeys({
        sourceExternalId: "do:loadbalancer:lb-1",
        targetExternalId: "do:droplet:5",
        relationship: "routes_to",
        evidence: "provider_reported",
        metadata: {},
      }),
    ).not.toContain("database_firewall:lb-1");
  });
});

describe("snapshot persistence through a sync", () => {
  let db: Database;
  let close: () => void;

  beforeEach(() => {
    ({ db, close } = createTestDb());
  });
  afterEach(() => close());

  const snapshotRows = () => db.select().from(snapshots).all();

  it("writes exactly one versioned, self-describing snapshot per run", async () => {
    const result = await runSync({ http: new FixtureDoHttp(), db });
    const rows = snapshotRows();

    expect(rows).toHaveLength(1);
    expect(rows[0]!.syncRunId).toBe(result.runId);
    expect(rows[0]!.snapshotVersion).toBe(SNAPSHOT_VERSION);
    const doc = rows[0]!.documentJson;
    expect(doc.syncRunId).toBe(result.runId);
    expect(doc.coverage.authoritativeKeys).toContain("database_firewall:db-orders");
    expect(doc.resources.length).toBeGreaterThan(0);
  });

  it("includes the internal trusts edge the v1 export omits", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const doc = snapshotRows()[0]!.documentJson;
    expect(doc.relationships.some((e) => e.relationship === "trusts")).toBe(true);
  });

  it("marks everything observed on a first full-ish run", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const doc = snapshotRows()[0]!.documentJson;
    expect(doc.resources.every((r) => r.freshness === "observed")).toBe(true);
  });

  it("stores no credential", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const serialised = JSON.stringify(snapshotRows()[0]!.documentJson);
    expect(serialised).not.toContain("dop_v1_");
    expect(serialised).not.toContain("REDACT-ME-fixture-password");
    expect(serialised).not.toContain("postgresql://");
  });

  it("retains and marks stale the database rows when a later run cannot see them", async () => {
    // A second run whose database listing fails keeps the last-known-good clusters, and the
    // snapshot must show them as retained rather than observed or dropped.
    class DatabasesBlind extends FixtureDoHttp {
      override async get<T>(pathOrUrl: string, query?: QueryParams): Promise<T> {
        if (pathOrUrl === "/v2/databases") throw new Error("503 Service Unavailable");
        return super.get<T>(pathOrUrl, query);
      }
    }

    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    clock.advance(60_000);
    await runSync({ http: new DatabasesBlind(), db, now: clock.now });

    const latest = snapshotRows().sort(
      (a, b) => a.createdAt.getTime() - b.createdAt.getTime(),
    ).at(-1)!;
    const doc = latest.documentJson;
    const dbResources = doc.resources.filter((r) => r.resourceType === "digitalocean.database_cluster");

    expect(dbResources.length).toBeGreaterThan(0);
    expect(dbResources.every((r) => r.freshness === "retained")).toBe(true);
    // Droplets were re-observed in the second run.
    expect(doc.resources.some((r) => r.resourceType === "digitalocean.droplet" && r.freshness === "observed")).toBe(true);
  });
});
