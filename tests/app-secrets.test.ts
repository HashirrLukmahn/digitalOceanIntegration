import { describe, expect, it } from "vitest";
import { emptyInventory, type RawInventory } from "../src/do/collectors";
import type { DoApp } from "../src/do/types";
import { evaluateExposure } from "../src/exposure/engine";
import { appPlaintextSecretEnvRule } from "../src/exposure/rules/app-secrets";
import { buildContext, type DraftFinding } from "../src/exposure/types";

/**
 * The rule detects credential-shaped variable NAMES left at the plaintext default.
 * Its most important property is what it does not do: read, store, or emit values.
 */

const evaluate = (apps: DoApp[]): DraftFinding[] => {
  const inventory: RawInventory = { ...emptyInventory(), apps };
  return appPlaintextSecretEnvRule.evaluate(buildContext(inventory));
};

const app = (envs: unknown[], componentEnvs: unknown[] = []): DoApp =>
  ({
    id: "app-1",
    spec: {
      name: "storefront",
      envs,
      services: componentEnvs.length > 0 ? [{ name: "web", envs: componentEnvs }] : undefined,
    },
  }) as DoApp;

describe("detection", () => {
  it.each([
    "STRIPE_API_KEY",
    "APIKEY",
    "SESSION_SECRET",
    "DB_PASSWORD",
    "GITHUB_TOKEN",
    "PRIVATE_KEY",
    "AWS_ACCESS_KEY",
    "SERVICE_CREDENTIALS",
    "DATABASE_URL",
    "REDIS_URL",
    "SENTRY_DSN",
  ])("flags %s when left at the GENERAL default", (key) => {
    const findings = evaluate([app([{ key, type: "GENERAL", value: "x" }])]);
    expect(findings).toHaveLength(1);
  });

  it("flags a variable with no type at all, since GENERAL is the default", () => {
    // The easiest way to leak a secret here is to simply omit `type`.
    const findings = evaluate([app([{ key: "API_KEY", value: "sk_live_x" }])]);
    expect(findings).toHaveLength(1);
  });

  it("does not flag a variable correctly marked SECRET", () => {
    expect(evaluate([app([{ key: "SESSION_SECRET", type: "SECRET", value: "EV[1:enc]" }])])).toHaveLength(0);
  });

  it.each(["LOG_LEVEL", "SORT_KEY", "PARTITION_KEY", "IDEMPOTENCY_KEY", "PORT", "NODE_ENV"])(
    "does not flag ordinary configuration named %s",
    (key) => {
      // A rule that fires on SORT_KEY teaches people to ignore it.
      expect(evaluate([app([{ key, type: "GENERAL", value: "v" }])])).toHaveLength(0);
    },
  );

  it("finds variables on components as well as on the app", () => {
    const findings = evaluate([
      app([{ key: "LOG_LEVEL", type: "GENERAL", value: "info" }], [
        { key: "STRIPE_API_KEY", type: "GENERAL", value: "sk_live_x" },
      ]),
    ]);
    expect(findings).toHaveLength(1);
    const variables = findings[0]!.evidence.variables as Array<{ component: string }>;
    expect(variables[0]!.component).toBe("service:web");
  });

  it("emits one finding per app listing every offender", () => {
    const findings = evaluate([
      app([
        { key: "API_KEY", type: "GENERAL", value: "a" },
        { key: "DB_PASSWORD", type: "GENERAL", value: "b" },
        { key: "LOG_LEVEL", type: "GENERAL", value: "info" },
      ]),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence.variables).toHaveLength(2);
  });

  it("produces nothing for an app with no variables", () => {
    expect(evaluate([{ id: "app-2" } as DoApp])).toHaveLength(0);
  });
});

describe("the rule never handles the value", () => {
  it("keeps the value out of the finding entirely", () => {
    const secret = "sk_live_THIS_MUST_NEVER_APPEAR";
    const findings = evaluate([app([{ key: "STRIPE_API_KEY", type: "GENERAL", value: secret }])]);

    const serialised = JSON.stringify(findings[0]);
    expect(serialised).not.toContain(secret);
    expect(serialised).not.toContain("sk_live");
    expect(findings[0]!.evidence.valuesInspected).toBe(false);
  });

  it("keeps a connection string's password out of the finding", () => {
    const findings = evaluate([
      app([
        { key: "DATABASE_URL", type: "GENERAL", value: "postgresql://u:hunter2@db.internal/app" },
      ]),
    ]);
    expect(JSON.stringify(findings[0])).not.toContain("hunter2");
  });
});

describe("classification as a non-reachability finding", () => {
  it("does not mark the app internet-exposed", () => {
    // A plaintext variable is a disclosure problem, not a reachability one. Letting it
    // set is_internet_exposed would corrupt the meaning of that column.
    const result = evaluateExposure("acct", {
      ...emptyInventory(),
      apps: [app([{ key: "API_KEY", type: "GENERAL", value: "x" }])],
    });

    expect(result.findings.some((f) => f.kind === "app.plaintext_secret_env")).toBe(true);
    expect(result.exposedResourceIds.has("do:app:app-1")).toBe(false);
  });

  it("still marks the app exposed when it also has a public ingress", () => {
    const withIngress = {
      ...app([{ key: "API_KEY", type: "GENERAL", value: "x" }]),
      live_url: "https://storefront.example",
    };
    const result = evaluateExposure("acct", { ...emptyInventory(), apps: [withIngress] });

    expect(result.exposedResourceIds.has("do:app:app-1")).toBe(true);
    expect(result.findings).toHaveLength(2);
  });
});

describe("fingerprint stability", () => {
  it("is unchanged when an unrelated variable is added", () => {
    const before = evaluate([app([{ key: "API_KEY", type: "GENERAL", value: "x" }])]);
    const after = evaluate([
      app([
        { key: "API_KEY", type: "GENERAL", value: "x" },
        { key: "LOG_LEVEL", type: "GENERAL", value: "info" },
      ]),
    ]);
    expect(after[0]!.stableElement).toBe(before[0]!.stableElement);
  });

  it("changes when another credential-shaped variable appears", () => {
    const before = evaluate([app([{ key: "API_KEY", type: "GENERAL", value: "x" }])]);
    const after = evaluate([
      app([
        { key: "API_KEY", type: "GENERAL", value: "x" },
        { key: "DB_PASSWORD", type: "GENERAL", value: "y" },
      ]),
    ]);
    expect(after[0]!.stableElement).not.toBe(before[0]!.stableElement);
  });
});
