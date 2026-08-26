import type { RawInventory } from "../do/collectors";
import { bySeverityDescending } from "./severity";
import {
  databasePublicNoTrustedSourcesRule,
  databaseTrustedSourceIsPublicRule,
  databaseVersionEndOfLifeRule,
} from "./rules/database";
import { appPlaintextSecretEnvRule } from "./rules/app-secrets";
import { certificateExpiringRule } from "./rules/certificate";
import { dropletNoFirewallRule, dropletOpenIngressRule } from "./rules/droplet";
import {
  appPublicIngressRule,
  kubernetesPublicEndpointRule,
  loadBalancerPublicRule,
} from "./rules/network";
import { kubernetesAutoUpgradeDisabledRule } from "./rules/kubernetes";
import { spacePublicReadRule } from "./rules/space";
import { buildContext, fingerprint, type DraftFinding, type ExposureRule } from "./types";

/**
 * The exposure engine.
 *
 * Every rule is deterministic and pure: same snapshot in, same findings out, with no
 * network access and no model in the loop. A language model may later *explain* a
 * finding, but nothing here asks one whether a finding exists.
 */

export const RULES: readonly ExposureRule[] = [
  dropletNoFirewallRule,
  dropletOpenIngressRule,
  loadBalancerPublicRule,
  databasePublicNoTrustedSourcesRule,
  databaseTrustedSourceIsPublicRule,
  databaseVersionEndOfLifeRule,
  kubernetesPublicEndpointRule,
  kubernetesAutoUpgradeDisabledRule,
  appPublicIngressRule,
  appPlaintextSecretEnvRule,
  certificateExpiringRule,
  spacePublicReadRule,
];

export interface EvaluatedFinding extends DraftFinding {
  /** Stable fingerprint; the primary key of `exposure_findings`. */
  id: string;
}

export interface ExposureResult {
  findings: EvaluatedFinding[];
  /** External ids of every resource with at least one finding. */
  exposedResourceIds: Set<string>;
}

export function evaluateExposure(
  accountId: string,
  inventory: RawInventory,
  rules: readonly ExposureRule[] = RULES,
  now: Date = new Date(),
): ExposureResult {
  const context = buildContext(inventory, now);
  const findings: EvaluatedFinding[] = [];
  const seen = new Set<string>();

  for (const rule of rules) {
    for (const draft of rule.evaluate(context)) {
      const id = fingerprint(accountId, draft);
      // Two rules could in principle converge on the same fingerprint; keep the first
      // so a run cannot produce duplicate primary keys.
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({ ...draft, id });
    }
  }

  findings.sort(bySeverityDescending);

  return {
    findings,
    // Only reachability findings mark a resource as internet-exposed. Every finding now
    // states this explicitly, so there is no default to reason about here.
    exposedResourceIds: new Set(
      findings
        .filter((f) => f.provesInternetExposure)
        .map((f) => f.resourceExternalId),
    ),
  };
}
