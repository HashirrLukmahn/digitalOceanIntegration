import { MockLanguageModelV3 } from "ai/test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setDbForTest } from "../src/db/client";
import { agentRuns } from "../src/db/schema";
import type { Database } from "../src/db/client";
import { FixtureDoHttp } from "../src/do/fixtures";
import { runAgent } from "../src/agent/run";
import { buildTools, withRepeatGuard } from "../src/agent/tools";
import { runSync } from "../src/sync/run";
import { createTestDb } from "./helpers/db";

/**
 * The model is mocked. What is under test is the harness around it: the terminal-tool
 * exit, the step-cap exit, the repeat guard, and that a run is always persisted.
 */

let db: Database;
let close: () => void;
let accountId: string;

beforeEach(async () => {
  ({ db, close } = createTestDb());
  setDbForTest(db);
  const sync = await runSync({ http: new FixtureDoHttp(), db });
  accountId = sync.accountId;
});

afterEach(() => {
  setDbForTest(undefined);
  close();
});

/** A model that emits one tool call, then stops. */
const modelCalling = (toolName: string, input: unknown) =>
  new MockLanguageModelV3({
    doGenerate: async () =>
      ({
        finishReason: "tool-calls",
        usage: { inputTokens: 1, outputTokens: 1, totalTokens: 2 },
        content: [
          {
            type: "tool-call",
            toolCallId: `call-${Math.random()}`,
            toolName,
            input: JSON.stringify(input),
          },
        ],
        warnings: [],
      }) as never,
  });

const runs = () => db.select().from(agentRuns).all();

describe("terminal tool", () => {
  it("completes when report_findings is called, and keeps a grounded chain", async () => {
    // The fixture graph has db-orders trusting droplet 101 (source=db-orders, target=101),
    // so travelling 101 -> db-orders is an *inbound* traversal of that trust edge.
    const chain = {
      title: "Public droplet reaches the orders database",
      severity: "high",
      hops: [
        { resourceExternalId: "do:droplet:101", findingKind: "droplet.public_ingress" },
        { resourceExternalId: "do:dbaas:db-orders", viaRelationship: "trusts", viaDirection: "inbound" },
      ],
      reasoning: "web-01 is internet-facing and the database trusts it as a source.",
      remediation: "Restrict web-01's public ingress, or remove it from the database's trusted sources.",
    };

    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", { findings: [chain] }),
    });

    expect(result.outcome).toBe("completed");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]!.title).toBe(chain.title);
    expect(result.findings[0]!.hops).toHaveLength(2);
  });

  it("treats an empty report as a complete, successful run", async () => {
    // The most important case: most accounts have no chains, and "found nothing"
    // must not look like a failure.
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", { findings: [] }),
    });

    expect(result.outcome).toBe("completed");
    expect(result.findings).toEqual([]);
  });

  it("drops a single-hop finding as a restated rule finding", async () => {
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "Droplet has SSH open",
            severity: "high",
            hops: [{ resourceExternalId: "do:droplet:101", findingKind: "droplet.public_ingress" }],
            reasoning: "restating the rule engine",
            remediation: "n/a",
          },
        ],
      }),
    });

    expect(result.outcome).toBe("completed");
    expect(result.findings).toEqual([]);
  });

  it("drops a chain whose hop edge is not in the graph (hallucinated pivot)", async () => {
    // droplet 101 and droplet 104 are both real, but nothing in the graph is a `trusts`
    // edge between them, so the claimed hop cannot be grounded.
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "Fabricated pivot between two droplets",
            severity: "high",
            hops: [
              { resourceExternalId: "do:droplet:101" },
              { resourceExternalId: "do:droplet:104", viaRelationship: "trusts", viaDirection: "outbound" },
            ],
            reasoning: "asserts an edge the stored graph does not contain",
            remediation: "irrelevant, should be dropped",
          },
        ],
      }),
    });

    expect(result.outcome).toBe("completed");
    expect(result.findings).toEqual([]);
  });

  it("drops a chain that cites a real edge in the wrong direction", async () => {
    // db-orders trusts droplet 101, so 101 -> db-orders is *inbound*. Claiming *outbound*
    // (as if droplet 101 were the truster) names a real edge backwards and must not ground.
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "Trust edge cited backwards",
            severity: "high",
            hops: [
              { resourceExternalId: "do:droplet:101" },
              { resourceExternalId: "do:dbaas:db-orders", viaRelationship: "trusts", viaDirection: "outbound" },
            ],
            reasoning: "right resources, wrong direction",
            remediation: "irrelevant, should be dropped",
          },
        ],
      }),
    });

    expect(result.findings).toEqual([]);
  });

  it("drops a grounded chain that ends at a non-sensitive resource", async () => {
    // lb-public routes_to droplet 101 (a real edge), and lb-public has a finding -- but a
    // droplet is not a sensitive target, so this is not a path worth reporting.
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "Path to a plain droplet",
            severity: "high",
            hops: [
              { resourceExternalId: "do:loadbalancer:lb-public", findingKind: "load_balancer.public_frontend" },
              { resourceExternalId: "do:droplet:101", viaRelationship: "routes_to", viaDirection: "outbound" },
            ],
            reasoning: "real edge, but the target is not sensitive",
            remediation: "n/a",
          },
        ],
      }),
    });

    expect(result.findings).toEqual([]);
  });

  it("drops a grounded chain with no remediation", async () => {
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "No fix offered",
            severity: "high",
            hops: [
              { resourceExternalId: "do:droplet:101", findingKind: "droplet.public_ingress" },
              { resourceExternalId: "do:dbaas:db-orders", viaRelationship: "trusts", viaDirection: "inbound" },
            ],
            reasoning: "grounded, but actionless",
            remediation: "   ",
          },
        ],
      }),
    });

    expect(result.findings).toEqual([]);
  });

  it("drops a chain that cites a supporting finding kind which does not exist", async () => {
    const result = await runAgent({
      accountId,
      model: modelCalling("report_findings", {
        findings: [
          {
            title: "Fabricated supporting finding",
            severity: "high",
            hops: [
              { resourceExternalId: "do:droplet:101", findingKind: "droplet.invented_finding" },
              { resourceExternalId: "do:dbaas:db-orders", viaRelationship: "trusts", viaDirection: "inbound" },
            ],
            reasoning: "entry cites a finding kind it does not have",
            remediation: "should still be dropped",
          },
        ],
      }),
    });

    expect(result.findings).toEqual([]);
  });

  it("records the pinned sync run id on the agent run", async () => {
    await runAgent({ accountId, model: modelCalling("report_findings", { findings: [] }) });
    const [run] = runs();
    expect(run!.snapshotSyncRunId).toBeTruthy();
  });
});

describe("step cap", () => {
  it("records incomplete, not empty-success, when the cap fires first", async () => {
    // A model that queries forever and never reports.
    const result = await runAgent({
      accountId,
      maxSteps: 3,
      model: modelCalling("query_resources", {}),
    });

    // The outcome is what matters: a run that never reported must not look like a
    // run that reported nothing. The exact step count is the SDK's bookkeeping.
    expect(result.outcome).toBe("incomplete");
    expect(result.findings).toEqual([]);
    expect(result.steps).toBeLessThanOrEqual(3);
  });
});

describe("persistence", () => {
  it("writes a row for every outcome, including failure", async () => {
    await runAgent({ accountId, model: modelCalling("report_findings", { findings: [] }) });

    const broken = new MockLanguageModelV3({
      doGenerate: async () => {
        throw new Error("upstream 500");
      },
    });
    const failed = await runAgent({ accountId, model: broken });

    expect(failed.outcome).toBe("failed");
    expect(failed.error).toContain("upstream 500");
    expect(runs()).toHaveLength(2);
  });

  it("records the tool calls made, for cost attribution and debugging", async () => {
    await runAgent({ accountId, model: modelCalling("report_findings", { findings: [] }) });
    const [run] = runs();
    expect(run!.toolCallsJson.map((c) => c.toolName)).toContain("report_findings");
  });

  it("sanitizes a token out of a persisted agent error", async () => {
    const leaky = new MockLanguageModelV3({
      doGenerate: async () => {
        throw new Error("failed with dop_v1_deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
      },
    });
    const result = await runAgent({ accountId, model: leaky });

    expect(result.error).not.toContain("dop_v1_");
    expect(JSON.stringify(runs())).not.toContain("dop_v1_");
  });
});

describe("repeat guard", () => {
  it("returns the prior result with a note instead of re-running", async () => {
    const tools = withRepeatGuard(buildTools(accountId));
    const query = tools.query_resources!.execute as (a: unknown, o: unknown) => Promise<unknown>;

    const first = await query({ resourceType: "digitalocean.droplet" }, {});
    const second = (await query({ resourceType: "digitalocean.droplet" }, {})) as {
      note: string;
      result: unknown;
    };

    expect(Array.isArray(first)).toBe(true);
    expect(second.note).toMatch(/already made this exact call/);
    expect(second.result).toEqual(first);
  });

  it("does not confuse different arguments for a repeat", async () => {
    const tools = withRepeatGuard(buildTools(accountId));
    const query = tools.query_resources!.execute as (a: unknown, o: unknown) => Promise<unknown>;

    const droplets = (await query({ resourceType: "digitalocean.droplet" }, {})) as unknown[];
    const databases = (await query(
      { resourceType: "digitalocean.database_cluster" },
      {},
    )) as unknown[];

    expect(droplets.length).toBeGreaterThan(0);
    expect(databases.length).toBeGreaterThan(0);
    expect(databases).not.toEqual(droplets);
  });
});

describe("tools read the snapshot", () => {
  it("exposes rule findings so the agent can build on them", async () => {
    const tools = buildTools(accountId);
    const findings = (await (
      tools.query_rule_findings!.execute as (a: unknown, o: unknown) => Promise<unknown[]>
    )({}, {})) as Array<{ kind: string }>;

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.kind === "droplet.public_ingress")).toBe(true);
  });

  it("exposes relationships for traversal", async () => {
    const tools = buildTools(accountId);
    const edges = (await (
      tools.query_relationships!.execute as (a: unknown, o: unknown) => Promise<{
        incoming: unknown[];
        outgoing: unknown[];
      }>
    )({ externalId: "do:droplet:101" }, {}))!;

    expect(edges.incoming.length + edges.outgoing.length).toBeGreaterThan(0);
  });
});
