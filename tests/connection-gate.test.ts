import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setDbForTest, type Database } from "../src/db/client";
import { connectionState } from "../src/connection/state";
import { FixtureDoHttp } from "../src/do/fixtures";
import { runSync } from "../src/sync/run";
import { createTestDb } from "./helpers/db";

/**
 * The gate defaults to off. A scanner that renders empty tables before anything is
 * connected reads as "your account is clean" rather than "nothing has been scanned",
 * and that false reassurance is the failure this product cannot afford.
 */

let db: Database;
let close: () => void;

beforeEach(() => {
  ({ db, close } = createTestDb());
  setDbForTest(db);
  delete process.env.DIGITALOCEAN_TOKEN;
});

afterEach(() => {
  setDbForTest(undefined);
  delete process.env.DIGITALOCEAN_TOKEN;
  close();
});

describe("connection stages", () => {
  it("starts disconnected with no credential at all", () => {
    const state = connectionState();
    expect(state.stage).toBe("disconnected");
    expect(state.source).toBe("none");
  });

  it("is connected-but-unsynced once a credential exists with no snapshot", () => {
    process.env.DIGITALOCEAN_TOKEN = "dop_v1_example";
    const state = connectionState();
    expect(state.stage).toBe("connected_unsynced");
    expect(state.source).toBe("environment");
  });

  it("is ready once a credential and a sync both exist", async () => {
    process.env.DIGITALOCEAN_TOKEN = "dop_v1_example";
    await runSync({ http: new FixtureDoHttp(), db });

    const state = connectionState();
    expect(state.stage).toBe("ready");
    expect(state.teamName).toBe("Acme Platform");
  });

  it("stays disconnected when a snapshot exists but the credential is gone", async () => {
    // Revoking the credential must close the app, not leave it open on stale data.
    process.env.DIGITALOCEAN_TOKEN = "dop_v1_example";
    await runSync({ http: new FixtureDoHttp(), db });
    delete process.env.DIGITALOCEAN_TOKEN;

    expect(connectionState().stage).toBe("disconnected");
  });
});
