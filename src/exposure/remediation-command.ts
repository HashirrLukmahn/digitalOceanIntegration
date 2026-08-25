/**
 * The exact command that fixes a finding.
 *
 * Derived from evidence the rules already store, so this is still a pure function of
 * the snapshot — deterministic, reproducible, and free. It runs at render time rather
 * than at sync time, which means findings recorded before this existed get commands
 * without a re-sync.
 *
 * Returns null when there is no single correct command. A wrong command pasted into a
 * production shell is worse than prose that made the reader think, so rules where the
 * fix genuinely depends on the operator's topology deliberately get nothing.
 */

const providerId = (externalId: string): string => externalId.split(":").slice(2).join(":");

interface OpenRule {
  firewallId?: unknown;
  protocol?: unknown;
  ports?: unknown;
  source?: unknown;
}

export interface RemediationCommand {
  command: string;
  /** What running it does, in one line. Shown above the command. */
  effect: string;
}

export function remediationCommand(
  kind: string,
  resourceExternalId: string,
  evidence: Record<string, unknown>,
): RemediationCommand | null {
  switch (kind) {
    case "droplet.public_ingress": {
      const rules = Array.isArray(evidence.openRules) ? (evidence.openRules as OpenRule[]) : [];
      const first = rules[0];
      if (!first?.firewallId || !first.protocol || first.ports === undefined) return null;

      // One --inbound-rules flag per offending rule, so a droplet with several
      // world-open rules gets them all removed in a single call.
      const flags = rules
        .filter((r) => r.firewallId === first.firewallId)
        .map(
          (r) =>
            `--inbound-rules "protocol:${String(r.protocol)},ports:${String(r.ports)},address:${String(r.source)}"`,
        )
        .join(" \\\n  ");

      return {
        effect: `Removes the rule(s) admitting the internet from firewall ${String(first.firewallId)}.`,
        command: `doctl compute firewall remove-rules ${String(first.firewallId)} \\\n  ${flags}`,
      };
    }

    case "database.trusted_source_is_public": {
      const sources = Array.isArray(evidence.publicTrustedSources)
        ? (evidence.publicTrustedSources as Array<{ value?: unknown }>)
        : [];
      const value = sources[0]?.value;
      if (!value) return null;

      return {
        effect: "Removes the trusted source that admits every address.",
        command: `doctl databases firewalls remove ${providerId(resourceExternalId)} --uuid "${String(value)}"`,
      };
    }

    case "database.public_no_trusted_sources": {
      return {
        effect:
          "Restricts the cluster to one droplet. Repeat --rule for each droplet, tag, or app " +
          "that needs access.",
        command:
          `doctl databases firewalls append ${providerId(resourceExternalId)} \\\n` +
          `  --rule droplet:DROPLET_ID`,
      };
    }

    case "kubernetes.public_control_plane": {
      return {
        effect: "Restricts the control plane to your administrative ranges.",
        command:
          `doctl kubernetes cluster update ${providerId(resourceExternalId)} \\\n` +
          `  --control-plane-firewall-enabled true \\\n` +
          `  --control-plane-firewall-allowed-addresses "YOUR_CIDR"`,
      };
    }

    // No command, and deliberately so:
    //
    // droplet.no_firewall      the right rule set depends entirely on what the box serves
    // load_balancer.public_frontend  being public is usually the point
    // app.public_ingress             same
    // app.plaintext_secret_env       the fix is an app-spec edit, not a CLI flag
    // space.public_read              needs an S3 client and the bucket's own credentials
    default:
      return null;
  }
}
