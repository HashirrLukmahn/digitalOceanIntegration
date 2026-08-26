import { describe, expect, it } from "vitest";
import { emptyInventory } from "../src/do/collectors";
import { evaluateExposure } from "../src/exposure/engine";
import {
  calibrateSeverity,
  deriveSeverity,
  severityEvidence,
  type Reachability,
  type SeverityModifier,
} from "../src/exposure/severity";
import type { Sensitivity } from "../src/normalize/resource";
import type { DoDroplet } from "../src/do/types";

/**
 * Severity model v2. Two axes now: severity (impact) from the matrix plus named,
 * bounded modifiers, and confidence (proof) carried alongside. The invariant that keeps
 * this safe to adopt is that with no modifiers the derived severity is exactly the old
 * matrix result, so no existing finding changes level.
 */

const SENSITIVITIES: Sensitivity[] = ["none", "credential", "datastore"];
const REACHABILITIES: Reachability[] = ["sensitive_ports", "all_ports", "web_ports", "restricted"];

describe("deriveSeverity", () => {
  it("equals the matrix for every input when there are no modifiers", () => {
    for (const s of SENSITIVITIES) {
      for (const r of REACHABILITIES) {
        expect(deriveSeverity(s, r).final).toBe(calibrateSeverity(s, r));
      }
    }
  });

  it("records base, final, and a readable formula", () => {
    const d = deriveSeverity("datastore", "sensitive_ports");
    expect(d.base).toBe("critical");
    expect(d.final).toBe("critical");
    expect(d.formula).toContain("datastore");
    expect(d.formula).toContain("⇒ critical");
  });

  it("shifts the rank by a positive modifier and names it in the formula", () => {
    const production: SeverityModifier = {
      label: "production environment",
      delta: 1,
      reason: "resource is in a Production project",
    };
    const d = deriveSeverity("none", "web_ports", [production]); // base is low
    expect(d.base).toBe("low");
    expect(d.final).toBe("medium");
    expect(d.formula).toContain("+1 (production environment)");
    expect(d.formula).toContain("⇒ medium");
  });

  it("clamps below low and above critical rather than leaving the vocabulary", () => {
    expect(
      deriveSeverity("none", "web_ports", [{ label: "x", delta: -5, reason: "" }]).final,
    ).toBe("low");
    expect(
      deriveSeverity("datastore", "sensitive_ports", [{ label: "y", delta: 5, reason: "" }]).final,
    ).toBe("critical");
  });
});

describe("severityEvidence", () => {
  it("packs confidence and a rationale block for the evidence panel", () => {
    const d = deriveSeverity("credential", "web_ports");
    const block = severityEvidence("provider_reported", d);

    expect(block.confidence).toBe("provider_reported");
    expect(block.severityRationale.final).toBe(d.final);
    expect(block.severityRationale.formula).toBe(d.formula);
    // The evidence block is display-facing; the raw axis inputs stay out of it.
    expect(block.severityRationale).not.toHaveProperty("sensitivity");
    expect(block.severityRationale).not.toHaveProperty("reachability");
  });
});

describe("rules attach confidence and a rationale to every finding", () => {
  const publicDroplet = {
    id: 1,
    name: "web",
    networks: { v4: [{ ip_address: "1.2.3.4", type: "public" }] },
  } as DoDroplet;

  it("carries a confidence and a severity formula through to the finding", () => {
    const result = evaluateExposure("acct", { ...emptyInventory(), droplets: [publicDroplet] });
    expect(result.findings.length).toBeGreaterThan(0);

    for (const finding of result.findings) {
      const evidence = finding.evidence as Record<string, unknown>;
      const rationale = evidence.severityRationale as { formula?: unknown } | undefined;

      expect(finding.confidence).toBeDefined();
      expect(typeof rationale?.formula).toBe("string");
      // Confidence is mirrored into evidence so it persists and renders.
      expect(evidence.confidence).toBe(finding.confidence);
    }
  });
});
