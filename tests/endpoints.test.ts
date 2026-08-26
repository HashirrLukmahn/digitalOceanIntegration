import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setDbForTest, type Database } from "../src/db/client";
import { tokenFingerprint } from "../src/lib/redact";
import { createTestDb } from "./helpers/db";

/**
 * The two endpoints answer different questions, and conflating them is the mistake
 * worth guarding against: /health must not depend on DigitalOcean, or their outage
 * takes your process down with it.
 */

let db: Database;
let close: () => void;

beforeEach(() => {
  ({ db, close } = createTestDb());
  setDbForTest(db);
});

afterEach(() => {
  setDbForTest(undefined);
  close();
});

describe("health is self-contained", () => {
  it("makes no outbound call", async () => {
    // If this ever needs the network, the endpoint has become a readiness check
    // wearing a liveness name — and a DigitalOcean outage would then take this
    // process down with it. Comments are stripped so prose about not calling
    // DigitalOcean does not count as calling it.
    const raw = await import("node:fs").then((fs) =>
      fs.readFileSync("app/api/health/route.ts", "utf8"),
    );
    const code = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

    expect(code).not.toMatch(/fetch\(/);
    expect(code).not.toMatch(/apiBaseUrl|digitalOceanCredential/);
  });
});

describe("status never exposes the credential", () => {
  it("fingerprints rather than returning the token", () => {
    const token = "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef";
    const fingerprint = tokenFingerprint(token);

    expect(fingerprint).toBe("****cdef");
    expect(fingerprint).not.toContain("dop_v1_");
    // Four characters is not enough to reconstruct anything.
    expect(fingerprint!.replace("****", "").length).toBe(4);
  });

  it("returns nothing for a missing credential", () => {
    expect(tokenFingerprint(undefined)).toBeNull();
  });
});

describe("chat persists identifiable messages", () => {
  it("assigns the assistant message an id server-side", async () => {
    // Without `generateMessageId` the SDK persists the assistant turn with an empty
    // id. One answer looks fine; a second one renders a sibling keyed "" and React
    // can no longer tell the two turns apart across a re-render. The id must be
    // assigned here rather than in the browser, because this is what gets stored and
    // read back when the conversation is reopened.
    const raw = await import("node:fs").then((fs) =>
      fs.readFileSync("app/api/chat/route.ts", "utf8"),
    );
    const code = raw.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

    expect(code).toMatch(/toUIMessageStreamResponse\(/);
    expect(code).toMatch(/generateMessageId:/);
  });
});
