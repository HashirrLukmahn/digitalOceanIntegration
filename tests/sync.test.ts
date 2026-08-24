import { eq } from "drizzle-orm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  cloudAccounts,
  cloudRelationships,
  cloudResources,
  exposureFindings,
  syncRuns,
} from "../src/db/schema";
import type { Database } from "../src/db/client";
import {
  COLLECTORS,
  CollectorUnavailableError,
  dropletsCollector,
  firewallsCollector,
  projectsCollector,
  type Collector,
} from "../src/do/collectors";
import { FixtureDoHttp } from "../src/do/fixtures";
import type { DoHttp, QueryParams } from "../src/do/http";
import { runSync } from "../src/sync/run";
import { createTestDb, fixedClock } from "./helpers/db";

let db: Database;
let close: () => void;

beforeEach(() => {
  ({ db, close } = createTestDb());
});

afterEach(() => close());

const rows = {
  resources: () => db.select().from(cloudResources).all(),
  findings: () => db.select().from(exposureFindings).all(),
  relationships: () => db.select().from(cloudRelationships).all(),
  runs: () => db.select().from(syncRuns).all(),
  accounts: () => db.select().from(cloudAccounts).all(),
};

describe("sync against the fixture account", () => {
  it("records the account and a terminal run", async () => {
    const result = await runSync({ http: new FixtureDoHttp(), db });

    expect(rows.accounts()).toHaveLength(1);
    expect(rows.accounts()[0]!.name).toBe("Acme Platform");
    expect(rows.runs()).toHaveLength(1);
    expect(rows.runs()[0]!.completedAt).not.toBeNull();
    expect(result.status).not.toBe("running");
  });

  it("follows pagination and stores droplets from every page", async () => {
    await runSync({ http: new FixtureDoHttp(), db });

    const droplets = rows.resources().filter((r) => r.resourceType === "digitalocean.droplet");
    // Two pages of two. Only following the first page would silently store two.
    expect(droplets).toHaveLength(4);
    expect(droplets.map((d) => d.name).sort()).toEqual([
      "api-02",
      "internal-worker",
      "legacy-reporting",
      "web-01",
    ]);
  });

  it("reports partial with Spaces listed as unavailable, not merely failed", async () => {
    const result = await runSync({ http: new FixtureDoHttp(), db });

    expect(result.status).toBe("partial");
    expect(result.coverage.unavailableCollectors.map((c) => c.collector)).toEqual(["spaces"]);
    expect(result.coverage.unavailableCollectors[0]!.message).toMatch(/S3-compatible API/);
    // Everything else ran.
    expect(result.coverage.failedCollectors).toEqual([]);
    expect(result.coverage.completedCollectors).toHaveLength(COLLECTORS.length - 1);
  });

  it("produces the expected findings and no false positives", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const findings = rows.findings();
    const byResource = new Map(findings.map((f) => [f.resourceExternalId, f]));

    // web-01: firewalled, but SSH is open to the world.
    expect(byResource.get("do:droplet:101")?.kind).toBe("droplet.public_ingress");
    expect(byResource.get("do:droplet:101")?.severity).toBe("high");

    // legacy-reporting: public with no firewall at all.
    expect(byResource.get("do:droplet:102")?.kind).toBe("droplet.no_firewall");

    // internal-worker is private, so no rule may touch it.
    expect(byResource.has("do:droplet:103")).toBe(false);

    // api-02 is the calibration case: its SSH is bastion-scoped via a TAG-attached
    // firewall, but 443 is open to the world. Same rule as web-01, low instead of
    // high, because a public HTTPS listener is ordinary and open SSH is not.
    expect(byResource.get("do:droplet:104")?.kind).toBe("droplet.public_ingress");
    expect(byResource.get("do:droplet:104")?.severity).toBe("low");

    // analytics trusts 0.0.0.0/0; orders names specific droplets.
    expect(byResource.get("do:dbaas:db-analytics")?.severity).toBe("critical");
    expect(byResource.has("do:dbaas:db-orders")).toBe(false);

    // Control-plane firewall explicitly disabled fires; restricted and null do not.
    expect(byResource.get("do:kubernetes:k8s-prod")?.severity).toBe("medium");
    expect(byResource.has("do:kubernetes:k8s-staging")).toBe(false);
    expect(byResource.has("do:kubernetes:k8s-legacy")).toBe(false);

    // Public edge load balancer and public app are recorded, but calibrated low.
    expect(byResource.get("do:loadbalancer:lb-public")?.severity).toBe("low");
    expect(byResource.has("do:loadbalancer:lb-internal")).toBe(false);
    expect(byResource.get("do:app:app-storefront")?.severity).toBe("low");
  });

  it("marks exactly the resources that have findings as internet-exposed", async () => {
    await runSync({ http: new FixtureDoHttp(), db });

    const exposed = rows
      .resources()
      .filter((r) => r.isInternetExposed)
      .map((r) => r.externalId)
      .sort();

    expect(exposed).toEqual([
      "do:app:app-storefront",
      "do:dbaas:db-analytics",
      "do:droplet:101",
      "do:droplet:102",
      "do:droplet:104",
      "do:kubernetes:k8s-prod",
      "do:loadbalancer:lb-public",
    ]);
  });

  it("derives relationships and drops URNs for uninventoried types", async () => {
    await runSync({ http: new FixtureDoHttp(), db });
    const edges = rows.relationships();

    const contains = edges.filter((e) => e.relationship === "contains");
    // The project lists an image URN, which this app does not inventory.
    expect(contains.some((e) => e.targetExternalId === "do:image:9999")).toBe(false);
    expect(contains.some((e) => e.targetExternalId === "do:droplet:101")).toBe(true);

    // Tag-attached firewall is recorded as derived, id-attached as provider-reported.
    const byTag = edges.find(
      (e) => e.sourceExternalId === "do:firewall:fw-api" && e.targetExternalId === "do:droplet:104",
    );
    expect(byTag?.evidence).toBe("derived");
    const byId = edges.find(
      (e) => e.sourceExternalId === "do:firewall:fw-web" && e.targetExternalId === "do:droplet:101",
    );
    expect(byId?.evidence).toBe("provider_reported");

    expect(
      edges.some(
        (e) => e.relationship === "routes_to" && e.sourceExternalId === "do:loadbalancer:lb-public",
      ),
    ).toBe(true);
    expect(
      edges.some(
        (e) => e.relationship === "depends_on" && e.targetExternalId === "do:dbaas:db-orders",
      ),
    ).toBe(true);
    expect(
      edges.some((e) => e.relationship === "attached_to" && e.sourceExternalId === "do:volume:vol-data-1"),
    ).toBe(true);
  });

  it("stores no credential anywhere in the database", async () => {
    await runSync({ http: new FixtureDoHttp(), db });

    const everything = JSON.stringify([
      rows.accounts(),
      rows.resources(),
      rows.findings(),
      rows.relationships(),
      rows.runs(),
    ]);

    expect(everything).not.toContain("REDACT-ME-fixture-password");
    expect(everything).not.toContain("postgresql://");
    expect(everything).not.toContain("mysql://");
    expect(everything).not.toContain("doadmin");
  });

  it("is idempotent: a second sync changes no counts and preserves first_seen_at", async () => {
    const clock = fixedClock();
    const first = await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    const firstSeen = rows.resources().map((r) => r.firstSeenAt!.getTime());

    clock.advance(60_000);
    const second = await runSync({ http: new FixtureDoHttp(), db, now: clock.now });

    expect(second.resourcesCount).toBe(first.resourcesCount);
    expect(second.findingsCount).toBe(first.findingsCount);
    expect(rows.resources().map((r) => r.firstSeenAt!.getTime())).toEqual(firstSeen);
    // last_seen_at moves forward, first_seen_at does not.
    expect(rows.resources().every((r) => r.lastSeenAt!.getTime() > r.firstSeenAt!.getTime())).toBe(true);
    expect(rows.resources().every((r) => r.removedAt === null)).toBe(true);
  });
});

describe("reconciliation", () => {
  /** A transport that serves the fixtures but drops droplet 102 from page one. */
  class WithoutLegacyDroplet extends FixtureDoHttp {
    override async get<T>(pathOrUrl: string, query?: QueryParams): Promise<T> {
      const body = await super.get<T>(pathOrUrl, query);
      if (pathOrUrl === "/v2/droplets") {
        const typed = body as { droplets: Array<{ id: number }> };
        return { ...typed, droplets: typed.droplets.filter((d) => d.id !== 102) } as T;
      }
      return body;
    }
  }

  it("marks a resource removed once it is absent from an authoritative run", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    expect(rows.resources().find((r) => r.externalId === "do:droplet:102")?.removedAt).toBeNull();

    clock.advance(60_000);
    await runSync({ http: new WithoutLegacyDroplet(), db, now: clock.now });

    const gone = rows.resources().find((r) => r.externalId === "do:droplet:102");
    expect(gone?.removedAt).not.toBeNull();
    // Other droplets are untouched.
    expect(rows.resources().find((r) => r.externalId === "do:droplet:101")?.removedAt).toBeNull();
  });

  it("resolves the finding attached to a removed resource", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    const before = rows.findings().find((f) => f.resourceExternalId === "do:droplet:102");
    expect(before?.resolvedAt).toBeNull();

    clock.advance(60_000);
    await runSync({ http: new WithoutLegacyDroplet(), db, now: clock.now });

    const after = rows.findings().find((f) => f.resourceExternalId === "do:droplet:102");
    expect(after?.resolvedAt).not.toBeNull();
    // The finding is retained, not deleted, so history survives.
    expect(after?.firstSeenAt).toEqual(before?.firstSeenAt);
  });

  it("does NOT reconcile a resource type whose collector failed", async () => {
    // This is the bug that would matter most in production: a transient failure of
    // one collector must not mark every resource of that type as deleted.
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    expect(rows.resources().filter((r) => r.resourceType === "digitalocean.droplet")).toHaveLength(4);

    const brokenDroplets: Collector = {
      ...dropletsCollector,
      async run() {
        throw new Error("upstream 503");
      },
    };

    clock.advance(60_000);
    const result = await runSync({
      http: new FixtureDoHttp(),
      db,
      now: clock.now,
      collectors: [projectsCollector, brokenDroplets, firewallsCollector],
    });

    expect(result.coverage.failedCollectors.map((c) => c.collector)).toEqual(["droplets"]);
    // Every droplet survives, unremoved, despite being absent from this run.
    const droplets = rows.resources().filter((r) => r.resourceType === "digitalocean.droplet");
    expect(droplets).toHaveLength(4);
    expect(droplets.every((d) => d.removedAt === null)).toBe(true);
  });

  it("still reconciles the types whose collectors did succeed", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });

    const brokenDroplets: Collector = {
      ...dropletsCollector,
      async run() {
        throw new Error("upstream 503");
      },
    };

    // Firewalls succeed but return nothing this run, so they are genuinely gone.
    const emptyFirewalls: Collector = { ...firewallsCollector, async run() {} };

    clock.advance(60_000);
    await runSync({
      http: new FixtureDoHttp(),
      db,
      now: clock.now,
      collectors: [brokenDroplets, emptyFirewalls],
    });

    const firewalls = rows.resources().filter((r) => r.resourceType === "digitalocean.firewall");
    expect(firewalls.length).toBeGreaterThan(0);
    expect(firewalls.every((f) => f.removedAt !== null)).toBe(true);
  });

  it("un-removes a resource that comes back", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });

    clock.advance(60_000);
    await runSync({ http: new WithoutLegacyDroplet(), db, now: clock.now });
    expect(rows.resources().find((r) => r.externalId === "do:droplet:102")?.removedAt).not.toBeNull();

    clock.advance(60_000);
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    expect(rows.resources().find((r) => r.externalId === "do:droplet:102")?.removedAt).toBeNull();
    expect(rows.findings().find((f) => f.resourceExternalId === "do:droplet:102")?.resolvedAt).toBeNull();
  });
});

describe("failure handling", () => {
  it("records a failed run against a known account when identity cannot be established", async () => {
    await runSync({ http: new FixtureDoHttp(), db });

    const brokenHttp: DoHttp = {
      async get() {
        throw new Error("network unreachable");
      },
    };
    const result = await runSync({ http: brokenHttp, db });

    expect(result.status).toBe("failed");
    expect(result.error).toContain("network unreachable");
    expect(rows.runs()).toHaveLength(2);
    // Nothing is reconciled away by a run that could not read anything.
    expect(rows.resources().every((r) => r.removedAt === null)).toBe(true);
  });

  it("propagates when there is no account and identity fails", async () => {
    const brokenHttp: DoHttp = {
      async get() {
        throw new Error("401 unauthorized");
      },
    };
    await expect(runSync({ http: brokenHttp, db })).rejects.toThrow(/401/);
  });

  it("distinguishes an unavailable collector from a failed one", async () => {
    const unavailable: Collector = {
      name: "spaces",
      required: false,
      resourceTypes: ["digitalocean.space"],
      async run() {
        throw new CollectorUnavailableError("no API for this");
      },
    };
    const failing: Collector = {
      name: "apps",
      required: false,
      resourceTypes: ["digitalocean.app"],
      async run() {
        throw new Error("boom");
      },
    };

    const result = await runSync({
      http: new FixtureDoHttp(),
      db,
      collectors: [projectsCollector, unavailable, failing],
    });

    expect(result.coverage.unavailableCollectors.map((c) => c.collector)).toEqual(["spaces"]);
    expect(result.coverage.failedCollectors.map((c) => c.collector)).toEqual(["apps"]);
    expect(result.status).toBe("partial");
  });

  it("sanitizes a token out of a persisted collector error", async () => {
    const leaky: Collector = {
      name: "droplets",
      required: true,
      resourceTypes: ["digitalocean.droplet"],
      async run() {
        throw new Error(
          "request failed: authorization: Bearer dop_v1_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
      },
    };

    const result = await runSync({
      http: new FixtureDoHttp(),
      db,
      collectors: [projectsCollector, leaky],
    });

    const message = result.coverage.failedCollectors[0]!.message;
    expect(message).not.toContain("dop_v1_");
    expect(message).toContain("[REDACTED]");
    expect(JSON.stringify(rows.runs())).not.toContain("dop_v1_");
  });
});

describe("sync run bookkeeping", () => {
  it("stores counts matching what was persisted", async () => {
    const result = await runSync({ http: new FixtureDoHttp(), db });
    const [run] = db.select().from(syncRuns).where(eq(syncRuns.id, result.runId)).all();

    expect(run!.resourcesCount).toBe(rows.resources().length);
    expect(run!.relationshipsCount).toBe(rows.relationships().length);
    expect(run!.findingsCount).toBe(rows.findings().length);
  });

  it("updates the account's last_synced_at", async () => {
    const clock = fixedClock();
    await runSync({ http: new FixtureDoHttp(), db, now: clock.now });
    expect(rows.accounts()[0]!.lastSyncedAt).not.toBeNull();
  });
});
