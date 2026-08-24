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

export function calibrateSeverity(
  sensitivity: Sensitivity,
  reachability: Reachability,
): Severity {
  return MATRIX[sensitivity][reachability];
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export function maxSeverity(a: Severity, b: Severity): Severity {
  return RANK[a] >= RANK[b] ? a : b;
}

/** Descending severity, for the findings list. */
export function bySeverityDescending<T extends { severity: Severity }>(a: T, b: T): number {
  return RANK[b.severity] - RANK[a.severity];
}
