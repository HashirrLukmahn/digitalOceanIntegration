import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setDbForTest, type Database } from "../src/db/client";
import { oauthStates } from "../src/db/schema";
import { decrypt, encrypt, hasMasterKey, MissingMasterKeyError } from "../src/oauth/crypto";
import { beginAuthorization, consumeState } from "../src/oauth/digitalocean";
import { createTestDb } from "./helpers/db";

const KEY = Buffer.alloc(32, 7).toString("base64");
const CONFIG = {
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "http://localhost:3000/api/connection/oauth/callback",
};

let db: Database;
let close: () => void;

beforeEach(() => {
  ({ db, close } = createTestDb());
  setDbForTest(db);
  process.env.TOKEN_MASTER_KEY = KEY;
});

afterEach(() => {
  setDbForTest(undefined);
  delete process.env.TOKEN_MASTER_KEY;
  close();
});

describe("token encryption", () => {
  it("round-trips", () => {
    const token = "doo_v1_abcdef0123456789";
    expect(decrypt(encrypt(token, "access_token"), "access_token")).toBe(token);
  });

  it("does not leave the token readable in the stored value", () => {
    const stored = encrypt("doo_v1_secret", "access_token");
    expect(Buffer.from(stored, "base64").toString("latin1")).not.toContain("doo_v1_");
  });

  it("refuses a ciphertext presented as a different field", () => {
    // Without the AAD binding, a stored access token could be swapped into the
    // refresh-token column and would still decrypt.
    const stored = encrypt("doo_v1_secret", "access_token");
    expect(() => decrypt(stored, "refresh_token")).toThrow();
  });

  it("refuses a tampered value", () => {
    const raw = Buffer.from(encrypt("doo_v1_secret", "access_token"), "base64");
    raw[raw.length - 1] = raw[raw.length - 1]! ^ 0xff;
    expect(() => decrypt(raw.toString("base64"), "access_token")).toThrow();
  });

  it("reports a missing master key rather than storing in the clear", () => {
    delete process.env.TOKEN_MASTER_KEY;
    expect(hasMasterKey()).toBe(false);
    expect(() => encrypt("x", "access_token")).toThrow(MissingMasterKeyError);
  });

  it("rejects a key that is not 32 bytes", () => {
    process.env.TOKEN_MASTER_KEY = Buffer.alloc(16, 1).toString("base64");
    expect(() => encrypt("x", "access_token")).toThrow(/32 bytes/);
  });
});

describe("authorization request", () => {
  it("uses the authorization code flow and never the implicit one", () => {
    const url = new URL(beginAuthorization(CONFIG));
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.origin + url.pathname).toBe("https://cloud.digitalocean.com/v1/oauth/authorize");
    expect(url.searchParams.get("scope")).toBe("api:read");
    expect(url.searchParams.get("redirect_uri")).toBe(CONFIG.redirectUri);
  });

  it("stores only a hash of the state, never the state itself", () => {
    const state = new URL(beginAuthorization(CONFIG)).searchParams.get("state")!;
    const rows = db.select().from(oauthStates).all();
    expect(rows[0]!.stateHash).not.toBe(state);
    expect(rows[0]!.stateHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("state consumption", () => {
  it("accepts a fresh state exactly once", () => {
    const state = new URL(beginAuthorization(CONFIG)).searchParams.get("state")!;
    expect(consumeState(state)).not.toBeNull();
    // A replayed callback must not spend the same authorization twice.
    expect(consumeState(state)).toBeNull();
  });

  it("rejects a state it never issued", () => {
    expect(consumeState("not-a-real-state")).toBeNull();
  });

  it("returns the redirect URI the flow started with", () => {
    const state = new URL(beginAuthorization(CONFIG)).searchParams.get("state")!;
    expect(consumeState(state)?.redirectUri).toBe(CONFIG.redirectUri);
  });
});
