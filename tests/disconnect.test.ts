import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setDbForTest, type Database } from "../src/db/client";
import { connectionState } from "../src/connection/state";
import { disconnect } from "../src/connection/disconnect";
import {
  chatThreads,
  cloudAccounts,
  cloudResources,
  exposureFindings,
  syncRuns,
} from "../src/db/schema";
import { FixtureDoHttp } from "../src/do/fixtures";
import { runSync } from "../src/sync/run";
import { createTestDb } from "./helpers/db";

/**
 * Disconnect has to leave nothing behind that could be mistaken for current data.
 * A scanner still showing findings for an account it can no longer reach is asserting
 * something it cannot check — and it reads as current.
 */

let db: Database;
let close: () => void;

beforeEach(async () => {
  ({ db, close } = createTestDb());
  setDbForTest(db);
  process.env.DIGITALOCEAN_TOKEN = "dop_v1_example";
  await runSync({ http: new FixtureDoHttp(), db });
});

afterEach(() => {
  setDbForTest(undefined);
  delete process.env.DIGITALOCEAN_TOKEN;
  close();
});

const rows = {
  accounts: () => db.select().from(cloudAccounts).all().length,
  resources: () => db.select().from(cloudResources).all().length,
  findings: () => db.select().from(exposureFindings).all().length,
  runs: () => db.select().from(syncRuns).all().length,
  threads: () => db.select().from(chatThreads).all().length,
};

describe("ending the connection", () => {
  it("starts from a populated snapshot", () => {
    expect(rows.resources()).toBeGreaterThan(0);
    expect(rows.findings()).toBeGreaterThan(0);
    expect(connectionState().stage).toBe("ready");
  });

  it("removes every trace of the synced account", () => {
    disconnect();

    expect(rows.accounts()).toBe(0);
    expect(rows.resources()).toBe(0);
    expect(rows.findings()).toBe(0);
    expect(rows.runs()).toBe(0);
  });

  it("closes the app even though the environment token is still set", () => {
    // The important case for a demo, and the one that is easy to get wrong: the PAT
    // in .env has not moved, so only destroying the snapshot actually shuts the door.
    expect(process.env.DIGITALOCEAN_TOKEN).toBeDefined();

    disconnect();

    const state = connectionState();
    expect(state.stage).not.toBe("ready");
    expect(state.teamName).toBeNull();
  });

  it("reports what it destroyed", () => {
    const before = { resources: rows.resources(), findings: rows.findings() };
    const result = disconnect();

    expect(result.removedResources).toBe(before.resources);
    expect(result.removedFindings).toBe(before.findings);
  });

  it("takes saved conversations with it", () => {
    // Not optional: chat_threads cascades from cloud_accounts. Which is correct — a
    // saved conversation cites resource ids that no longer exist.
    db.insert(chatThreads)
      .values({
        id: "t1",
        accountId: db.select().from(cloudAccounts).all()[0]!.id,
        title: "demo",
        messagesJson: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      })
      .run();
    expect(rows.threads()).toBe(1);

    disconnect();
    expect(rows.threads()).toBe(0);
  });

  it("is safe to run twice", () => {
    disconnect();
    expect(() => disconnect()).not.toThrow();
    expect(rows.resources()).toBe(0);
  });
});
