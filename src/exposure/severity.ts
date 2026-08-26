import type { Sensitivity } from "../normalize/resource";

export type Severity = "low" | "medium" | "high" | "critical";

/**
 * How much of the resource the internet can actually reach.
 *
 * This is the axis the specification cares about most: "Do not mark every resource
 * with a public IP vulnerable." A public HTTPS listener is usually the entire point of
 * the machine; a public Redis port never is.
 */
export type Reachability =
  /** Sensitive administrative or database ports reachable from the internet. */
  | "sensitive_ports"
  /** Every port open to the internet. */
  | "all_ports"
  /** Only ordinary web ports (80/443/8080/8443). */
  | "web_ports"
  /** Publicly addressable, but access is restricted by an allowlist or equivalent. */
  | "restricted";

/**
 * Severity is a function of what the resource holds and how much of it is reachable.
 *
 * Reading the table: a load balancer serving HTTPS to the world is `low` -- recorded,
 * because the inventory should know about it, but not dressed up as an incident. A
 * managed database reachable from `0.0.0.0/0` is `critical`, because the blast radius
 * is the data itself and there is no benign reading of it.
 */
const MATRIX: Record<Sensitivity, Record<Reachability, Severity>> = {
  datastore: {
    sensitive_ports: "critical",
    all_ports: "critical",
    web_ports: "high",
    restricted: "medium",
  },
  credential: {
    sensitive_ports: "critical",
    all_ports: "high",
    web_ports: "medium",
    restricted: "low",
  },
  none: {
    sensitive_ports: "high",
    all_ports: "high",
    web_ports: "low",
    restricted: "low",
  },
};

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
const ORDERED: readonly Severity[] = ["low", "medium", "high", "critical"];

/**
 * How strongly the evidence supports the claim -- an axis *orthogonal* to severity.
 *
 * Severity is impact; confidence is proof. Keeping them separate is what stops a
 * high-impact guess (a DNS record pointing outside our inventory, say) from rendering as
 * a verified critical. Every finding carries both.
 *
 *   provider_reported  a value DigitalOcean stated directly (network=EXTERNAL, a 0.0.0.0/0
 *                      firewall rule, type=GENERAL on a variable).
 *   derived            deterministically inferred from *complete* provider data (a public
 *                      droplet with no firewall attached by id or tag).
 *   active_probe       observed by an explicitly enabled read-only check (an anonymous
 *                      request that listed a Spaces bucket -- proof by demonstration).
 *   heuristic          suspicious but not sufficient to prove exploitability (stale DNS).
 */
export type Confidence = "provider_reported" | "derived" | "active_probe" | "heuristic";

/**
 * One bounded, named adjustment to the base severity.
 *
 * Deliberately discrete: `delta` is a small integer that shifts the severity *rank*, not
 * a weight in a scoring formula. The point is that "+1 because the resource is in a
 * Production project" is a sentence a reviewer can check, where "risk score 7.3" is not.
 */
export interface SeverityModifier {
  label: string;
  /** Rank shift; the result is clamped to [low, critical]. Keep to -1/+1 in practice. */
  delta: number;
  reason: string;
}

/** The full, auditable derivation of a finding's severity. */
export interface SeverityDerivation {
  sensitivity: Sensitivity;
  reachability: Reachability;
  base: Severity;
  modifiers: SeverityModifier[];
  final: Severity;
  /** Human-readable one-liner, e.g. "datastore data × sensitive-port reachability ⇒ critical". */
  formula: string;
}

const SENSITIVITY_LABEL: Record<Sensitivity, string> = {
  none: "non-sensitive resource",
  credential: "credential-bearing resource",
  datastore: "datastore",
};

const REACHABILITY_LABEL: Record<Reachability, string> = {
  sensitive_ports: "sensitive-port reachability",
  all_ports: "all-ports reachability",
  web_ports: "web-port reachability",
  restricted: "restricted access",
};

function severityFromRank(rank: number): Severity {
  return ORDERED[Math.max(0, Math.min(ORDERED.length - 1, rank))]!;
}

/**
 * Derive a severity *and* the trace that explains it.
 *
 * The base still comes from the sensitivity × reachability matrix. Modifiers then shift
 * the rank by small, named amounts and the result is clamped back into the four levels,
 * so severity never leaves the vocabulary the interface renders. With no modifiers the
 * result is identical to the old `calibrateSeverity`, which is why adopting this changes
 * no existing finding.
 */
export function deriveSeverity(
  sensitivity: Sensitivity,
  reachability: Reachability,
  modifiers: SeverityModifier[] = [],
): SeverityDerivation {
  const base = MATRIX[sensitivity][reachability];
  const rank = modifiers.reduce((acc, m) => acc + m.delta, RANK[base]);
  const final = severityFromRank(rank);

  let formula = `${SENSITIVITY_LABEL[sensitivity]} × ${REACHABILITY_LABEL[reachability]} ⇒ ${base}`;
  if (modifiers.length > 0) {
    const steps = modifiers
      .map((m) => `${m.delta >= 0 ? "+" : ""}${m.delta} (${m.label})`)
      .join(", ");
    formula += ` then ${steps} ⇒ ${final}`;
  }

  return { sensitivity, reachability, base, modifiers, final, formula };
}

/** The four levels the matrix can produce, unchanged. Delegates to {@link deriveSeverity}. */
export function calibrateSeverity(
  sensitivity: Sensitivity,
  reachability: Reachability,
): Severity {
  return MATRIX[sensitivity][reachability];
}

/**
 * The block a rule spreads into its `evidence` so the severity is self-explaining.
 *
 * Surfaced through `evidence` rather than as a new top-level finding column on purpose:
 * it persists, exports, and renders through the existing evidence panel with no schema
 * migration and no change to the export contract (whose top-level keys are pinned by a
 * test). `confidence` rides alongside so impact and proof are always shown together.
 */
export function severityEvidence(
  confidence: Confidence,
  derivation: SeverityDerivation,
): { confidence: Confidence; severityRationale: Omit<SeverityDerivation, "sensitivity" | "reachability"> } {
  return {
    confidence,
    severityRationale: {
      base: derivation.base,
      modifiers: derivation.modifiers,
      final: derivation.final,
      formula: derivation.formula,
    },
  };
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

/** Descending severity, for the findings list. */
export function bySeverityDescending<T extends { severity: Severity }>(a: T, b: T): number {
  return RANK[b.severity] - RANK[a.severity];
}
