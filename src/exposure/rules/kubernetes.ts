import { externalId } from "../../normalize/resource";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * Kubernetes cluster upgrade posture.
 *
 * DigitalOcean can auto-apply **patch** upgrades to a DOKS cluster (`auto_upgrade`). It
 * does not auto-apply minor-version upgrades, which stay a manual action -- so this rule is
 * careful to claim only what the flag actually means. With auto-upgrade off, patch releases
 * that fix known CVEs (the IngressNightmare class of issue) are applied only when an
 * operator gets to them, which is a real but moderate gap rather than an open door.
 *
 * It fires *only* when the provider reports `auto_upgrade` as an explicit `false`. An absent
 * field means "this API response did not tell us", not "off": guessing there would raise a
 * finding on every cluster whose response omits the flag.
 */
export const kubernetesAutoUpgradeDisabledRule: ExposureRule = {
  kind: "kubernetes.auto_upgrade_disabled",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const cluster of inventory.kubernetes) {
      if (cluster.auto_upgrade !== false) continue; // absent = unknown, true = fine

      findings.push({
        resourceExternalId: externalId("kubernetes", cluster.id),
        kind: "kubernetes.auto_upgrade_disabled",
        severity: "low",
        confidence: "provider_reported",
        provesInternetExposure: false,
        title: "Kubernetes cluster does not auto-apply patch upgrades",
        summary:
          `Cluster "${cluster.name}" has automatic upgrades disabled, so DigitalOcean will not ` +
          `apply patch releases -- including security patches for known CVEs -- until someone ` +
          `upgrades it manually. Automatic upgrades cover patch versions only; minor-version ` +
          `upgrades remain a manual action either way.`,
        evidence: {
          confidence: "provider_reported",
          severityRationale: {
            base: "low",
            modifiers: [],
            final: "low",
            formula: "auto-upgrade disabled ⇒ patch CVEs applied only on manual action ⇒ low",
          },
          autoUpgrade: false,
          version: cluster.version ?? null,
          note: "Automatic upgrades apply patch versions only, never minor-version upgrades.",
        },
        remediation:
          "Enable automatic upgrades on the cluster, or establish a documented process that " +
          "applies patch releases promptly. Confirm a maintenance window is set so upgrades " +
          "land predictably.",
        stableElement: "auto-upgrade-disabled",
        coverageKeys: ["kubernetes"],
      });
    }

    return findings;
  },
};
