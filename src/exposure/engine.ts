import type { RawInventory } from "../do/collectors";
import { deriveRelationships, type DerivedRelationship } from "../relationships/derive";
import { bySeverityDescending } from "./severity";
import {
  databasePublicNoTrustedSourcesRule,
  databaseTrustedSourceIsPublicRule,
  databaseVersionEndOfLifeRule,
} from "./rules/database";
import { appPlaintextSecretEnvRule } from "./rules/app-secrets";
import { certificateExpiringRule } from "./rules/certificate";
import { dnsRecordToUnassignedReservedIpRule, reservedIpUnassignedRule } from "./rules/dns";
import { dropletNoFirewallRule, dropletOpenIngressRule } from "./rules/droplet";
import {
  appPublicIngressRule,
  kubernetesPublicEndpointRule,
  loadBalancerPublicRule,
  loadBalancerSensitiveBackendPortRule,
} from "./rules/network";
import {
  kubernetesAutoUpgradeDisabledRule,
  kubernetesUpgradeAvailableRule,
} from "./rules/kubernetes";
import { spacePublicReadRule } from "./rules/space";
import {
  exposedAppLeaksDatastoreCredentialRule,
  publicWorkloadToDatastoreRule,
} from "./rules/path";
import {
  buildContext,
  fingerprint,
  type DraftFinding,
  type ExposureRule,
  type PathContext,
  type PathRule,
  type RuleContract,
} from "./types";

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
  loadBalancerSensitiveBackendPortRule,
  databasePublicNoTrustedSourcesRule,
  databaseTrustedSourceIsPublicRule,
  databaseVersionEndOfLifeRule,
  kubernetesPublicEndpointRule,
  kubernetesAutoUpgradeDisabledRule,
  kubernetesUpgradeAvailableRule,
  appPublicIngressRule,
  appPlaintextSecretEnvRule,
  certificateExpiringRule,
  reservedIpUnassignedRule,
  dnsRecordToUnassignedReservedIpRule,
  spacePublicReadRule,
];

/**
 * Path rules run in a second phase, after {@link RULES}, so they can read the base
 * findings and the trust graph. They describe *combinations* -- an exposed workload a
 * datastore trusts -- rather than single-resource misconfigurations.
 */
export const PATH_RULES: readonly PathRule[] = [
  publicWorkloadToDatastoreRule,
  exposedAppLeaksDatastoreCredentialRule,
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

export interface EvaluateOptions {
  rules?: readonly ExposureRule[];
  pathRules?: readonly PathRule[];
  now?: Date;
  /** Pre-derived relationships; recomputed from the inventory if omitted. */
  relationships?: readonly DerivedRelationship[];
  /**
   * The granular coverage keys authoritative this run. When supplied, a rule whose
   * `requires` are not all present is skipped. Omit to run every rule (unit tests).
   */
  authoritativeKeys?: ReadonlySet<string>;
}

export function evaluateExposure(
  accountId: string,
  inventory: RawInventory,
  options: EvaluateOptions = {},
): ExposureResult {
  const rules = options.rules ?? RULES;
  const pathRules = options.pathRules ?? PATH_RULES;
  const now = options.now ?? new Date();
  const context = buildContext(inventory, now);

  // A rule runs only if the collectors it requires were authoritative this run. When no
  // coverage is supplied (unit tests, ad-hoc calls) every rule runs -- gating is a
  // production safeguard, not a change to a rule's own logic. This is what stops a failed
  // firewalls collector from turning `droplet.no_firewall` into a false positive on every
  // public droplet: the rule is skipped, not fed an empty firewall list.
  const authoritativeKeys = options.authoritativeKeys;
  const canRun = (rule: RuleContract): boolean =>
    !authoritativeKeys || !rule.requires || rule.requires.every((key) => authoritativeKeys.has(key));

  const findings: EvaluatedFinding[] = [];
  const seen = new Set<string>();
  const collect = (draft: DraftFinding): void => {
    const id = fingerprint(accountId, draft);
    // Two rules could in principle converge on the same fingerprint; keep the first
    // so a run cannot produce duplicate primary keys.
    if (seen.has(id)) return;
    seen.add(id);
    findings.push({ ...draft, id });
  };

  // --- Phase 1: base rules -------------------------------------------------------
  for (const rule of rules) {
    if (!canRun(rule)) continue;
    for (const draft of rule.evaluate(context)) collect(draft);
  }

  // Only reachability findings mark a resource as internet-exposed. This set is computed
  // from phase one alone, and it is what the path rules build on -- a path finding is about
  // *indirect* reachability, so it never adds to this set.
  const exposedResourceIds = new Set(
    findings.filter((f) => f.provesInternetExposure).map((f) => f.resourceExternalId),
  );

  // --- Phase 2: path rules -------------------------------------------------------
  const relationships = options.relationships ?? deriveRelationships(inventory);
  const findingsByResource = new Map<string, DraftFinding[]>();
  for (const finding of findings) {
    const list = findingsByResource.get(finding.resourceExternalId) ?? [];
    list.push(finding);
    findingsByResource.set(finding.resourceExternalId, list);
  }
  const pathContext: PathContext = { ...context, relationships, exposedResourceIds, findingsByResource };
  for (const rule of pathRules) {
    if (!canRun(rule)) continue;
    for (const draft of rule.evaluate(pathContext)) collect(draft);
  }

  findings.sort(bySeverityDescending);

  return { findings, exposedResourceIds };
}
