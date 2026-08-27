import { externalId } from "../../normalize/resource";
import type { DraftFinding, ExposureRule } from "../types";

/** Parse a DOKS version like `1.31.1-do.0` into numeric components, or null if malformed. */
function parseK8sVersion(value: string | undefined): { major: number; minor: number; patch: number } | null {
  if (!value) return null;
  const core = value.split("-")[0] ?? "";
  const parts = core.split(".").map(Number);
  if (parts.length < 3 || parts.slice(0, 3).some((n) => !Number.isInteger(n))) return null;
  return { major: parts[0]!, minor: parts[1]!, patch: parts[2]! };
}

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
  requires: ["kubernetes"],
  references: ["https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/"],
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

/**
 * A Kubernetes cluster with upgrades the provider says are available.
 *
 * Driven entirely by DigitalOcean's per-cluster available-upgrades listing -- no
 * hand-maintained version table. It is careful about what "an upgrade is available" means:
 * it does **not** prove the installed release is unsupported or end-of-life, so the finding
 * makes no such claim. What it can say precisely is whether a *patch* upgrade (same
 * major.minor, higher patch) is on offer -- patch releases carry security fixes and are
 * exactly what auto-upgrade applies -- versus only newer minor versions, which are a
 * currency/feature choice rather than a security gap.
 *
 * Fires only when the provider actually returned target versions. An absent listing (the
 * child call was not made or failed) is unknown, not "up to date", so nothing is reported.
 */
export const kubernetesUpgradeAvailableRule: ExposureRule = {
  kind: "kubernetes.upgrade_available",
  requires: ["kubernetes"],
  references: ["https://docs.digitalocean.com/products/kubernetes/details/supported-releases/"],
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const cluster of inventory.kubernetes) {
      const upgrades = inventory.kubernetesUpgrades[cluster.id];
      if (upgrades === undefined) continue; // not fetched -> unknown
      if (upgrades.length === 0) continue; // provider says up to date

      const installed = parseK8sVersion(cluster.version);
      const targets = upgrades
        .map((u) => u.kubernetes_version ?? u.slug ?? "")
        .filter(Boolean);

      const patchUpgradeAvailable =
        installed !== null &&
        upgrades.some((u) => {
          const target = parseK8sVersion(u.kubernetes_version ?? u.slug);
          return (
            target !== null &&
            target.major === installed.major &&
            target.minor === installed.minor &&
            target.patch > installed.patch
          );
        });

      findings.push({
        resourceExternalId: externalId("kubernetes", cluster.id),
        kind: "kubernetes.upgrade_available",
        severity: "low",
        confidence: "provider_reported",
        provesInternetExposure: false,
        title: patchUpgradeAvailable
          ? "Kubernetes cluster is behind on available patch upgrades"
          : "Kubernetes cluster has newer versions available",
        summary:
          `Cluster "${cluster.name}" runs ${cluster.version ?? "an unknown version"}, and ` +
          `DigitalOcean lists ${targets.length} available upgrade target(s)` +
          (targets.length > 0 ? ` (${targets.join(", ")})` : "") +
          `. ` +
          (patchUpgradeAvailable
            ? "A patch upgrade is available; patch releases carry security fixes, and automatic " +
              "upgrades apply them when enabled."
            : "Only newer minor versions are available, which is a currency choice rather than a " +
              "security gap.") +
          " This does not mean the installed version is unsupported.",
        evidence: {
          confidence: "provider_reported",
          severityRationale: {
            base: "low",
            modifiers: [],
            final: "low",
            formula: patchUpgradeAvailable
              ? "patch upgrade available (may carry security fixes) ⇒ low"
              : "newer minor version available (currency, not a security gap) ⇒ low",
          },
          installedVersion: cluster.version ?? null,
          availableUpgradeVersions: targets,
          patchUpgradeAvailable,
          autoUpgrade: cluster.auto_upgrade ?? null,
          note: "An available upgrade does not prove the installed release is end-of-life or unsupported.",
        },
        remediation: patchUpgradeAvailable
          ? "Apply the available patch upgrade, or enable automatic upgrades so patch releases " +
            "land promptly. Schedule a maintenance window so the upgrade is predictable."
          : "Plan a minor-version upgrade when convenient, testing workloads against the target " +
            "version first. No urgent action is required on security grounds alone.",
        stableElement: "upgrade-available",
        coverageKeys: ["kubernetes", `kubernetes_upgrades:${cluster.id}`],
      });
    }

    return findings;
  },
};
