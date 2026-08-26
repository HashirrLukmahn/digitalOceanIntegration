import { externalId } from "../../normalize/resource";
import {
  anyPublicInternetSource,
  describePorts,
  parsePorts,
  sensitivePortsInRange,
} from "../ports";
import {
  calibrateSeverity,
  deriveSeverity,
  maxSeverity,
  severityEvidence,
  type Reachability,
} from "../severity";
import { publicAddresses, type DraftFinding, type ExposureRule } from "../types";

/**
 * Droplet exposure.
 *
 * Both rules require a public address first. A droplet with only a private VPC
 * interface is not internet-exposed no matter how permissive its firewall is, and
 * reporting one would be a false positive of exactly the kind that trains people to
 * ignore the tool.
 */

/**
 * A public droplet with no firewall attached at all.
 *
 * DigitalOcean attaches cloud firewalls either by droplet id or by tag; both are
 * resolved in `indexFirewallsByDroplet`. Missing the tag path would report correctly
 * firewalled droplets as naked, which is worse than missing the finding entirely.
 *
 * With no firewall, DigitalOcean applies no filtering -- whatever the operating system
 * listens on is reachable. That is why reachability is `all_ports` rather than being
 * inferred from any rule.
 */
export const dropletNoFirewallRule: ExposureRule = {
  kind: "droplet.no_firewall",
  evaluate({ inventory, firewallsByDropletId }) {
    const findings: DraftFinding[] = [];

    for (const droplet of inventory.droplets) {
      const publicIps = publicAddresses(droplet);
      if (publicIps.length === 0) continue;

      const firewalls = firewallsByDropletId.get(droplet.id) ?? [];
      if (firewalls.length > 0) continue;

      // Derived, not provider-reported: the exposure is inferred from a public IP plus the
      // *absence* of any attached firewall in a complete firewall listing.
      const derivation = deriveSeverity("none", "all_ports");

      findings.push({
        resourceExternalId: externalId("droplet", droplet.id),
        kind: "droplet.no_firewall",
        severity: derivation.final,
        confidence: "derived",
        provesInternetExposure: true,
        title: "Droplet has a public IP and no cloud firewall",
        summary:
          `Droplet "${droplet.name}" is reachable at ${publicIps.join(", ")} and has no ` +
          `DigitalOcean cloud firewall attached, by id or by tag. Every port its operating ` +
          `system listens on is reachable from the internet.`,
        evidence: {
          ...severityEvidence("derived", derivation),
          publicAddresses: publicIps,
          attachedFirewallCount: 0,
          dropletTags: droplet.tags ?? [],
          // Naming the checks performed matters: the absence of a firewall is only
          // meaningful if the reader knows tag attachment was considered.
          checkedAttachmentMethods: ["firewall.droplet_ids", "firewall.tags"],
        },
        remediation:
          "Attach a cloud firewall that allows only the ports this droplet needs to serve, " +
          "restricted to known source ranges. Administrative ports such as SSH should be " +
          "limited to a bastion or VPN range rather than 0.0.0.0/0.",
        stableElement: "no-firewall",
      });
    }

    return findings;
  },
};

interface OpenRule {
  firewallId: string;
  firewallName: string;
  protocol: string;
  ports: string;
  source: string;
  description: string;
  sensitiveServices: Array<{ port: number; service: string }>;
  allPorts: boolean;
}

/**
 * A public droplet whose firewall admits `0.0.0.0/0` or `::/0` on one or more ports.
 *
 * One finding per droplet, not per firewall rule. The specification is explicit that a
 * row is an actionable exposure rather than a raw rule, and a droplet with five
 * world-open rules is one problem to think about, not five. Every contributing rule is
 * still listed individually in the evidence, so the reviewer can see precisely what to
 * change.
 */
export const dropletOpenIngressRule: ExposureRule = {
  kind: "droplet.public_ingress",
  evaluate({ inventory, firewallsByDropletId }) {
    const findings: DraftFinding[] = [];

    for (const droplet of inventory.droplets) {
      const publicIps = publicAddresses(droplet);
      if (publicIps.length === 0) continue;

      const openRules: OpenRule[] = [];

      for (const firewall of firewallsByDropletId.get(droplet.id) ?? []) {
        for (const rule of firewall.inbound_rules ?? []) {
          const source = anyPublicInternetSource(rule.sources?.addresses);
          if (!source) continue;

          const range = parsePorts(rule.ports);
          openRules.push({
            firewallId: firewall.id,
            firewallName: firewall.name,
            protocol: rule.protocol,
            ports: rule.ports,
            source,
            description: describePorts(range, rule.protocol),
            sensitiveServices: sensitivePortsInRange(range),
            allPorts: range.all,
          });
        }
      }

      if (openRules.length === 0) continue;

      // Severity follows the worst rule: one wide-open SSH rule is not softened by
      // three well-scoped HTTPS rules sitting next to it.
      let reachability: Reachability = "web_ports";
      let severity = calibrateSeverity("none", "web_ports");
      for (const rule of openRules) {
        const ruleReachability: Reachability =
          rule.sensitiveServices.length > 0
            ? "sensitive_ports"
            : rule.allPorts
              ? "all_ports"
              : "web_ports";
        severity = maxSeverity(severity, calibrateSeverity("none", ruleReachability));
        if (ruleReachability === "sensitive_ports") reachability = "sensitive_ports";
        else if (ruleReachability === "all_ports" && reachability !== "sensitive_ports") {
          reachability = "all_ports";
        }
      }

      const services = [
        ...new Set(openRules.flatMap((r) => r.sensitiveServices.map((s) => s.service))),
      ];

      // The open rule is stated verbatim by DigitalOcean, so provider_reported. The
      // derivation reflects the worst reachability, so `derivation.final === severity`;
      // the loop's `severity` stays authoritative and the derivation only explains it.
      const derivation = deriveSeverity("none", reachability);

      findings.push({
        resourceExternalId: externalId("droplet", droplet.id),
        kind: "droplet.public_ingress",
        severity,
        confidence: "provider_reported",
        provesInternetExposure: true,
        title:
          services.length > 0
            ? `Droplet exposes ${services.join(", ")} to the internet`
            : "Droplet accepts inbound traffic from the internet",
        summary:
          `Droplet "${droplet.name}" is reachable at ${publicIps.join(", ")}, and its firewall ` +
          `admits traffic from the entire internet on ${openRules
            .map((r) => r.description)
            .join(", ")}.` +
          (services.length > 0
            ? ` This includes ${services.join(", ")}, which should not be internet-facing.`
            : ""),
        evidence: {
          ...severityEvidence("provider_reported", derivation),
          publicAddresses: publicIps,
          reachability,
          openRules: openRules.map((r) => ({
            firewallId: r.firewallId,
            firewallName: r.firewallName,
            protocol: r.protocol,
            ports: r.ports,
            // "0" means every port; spell it out so the evidence is not misread.
            portsMeaning: r.description,
            source: r.source,
            sensitiveServices: r.sensitiveServices,
          })),
        },
        remediation:
          services.length > 0
            ? `Restrict the firewall rules covering ${services.join(", ")} to specific source ` +
              "ranges such as a VPN or bastion, or move the service behind a private network."
            : "Narrow the source range on these inbound rules to the networks that genuinely " +
              "need access. If the service is intentionally public, no change is needed.",
        // Sorted so rule ordering from the API cannot change the fingerprint.
        stableElement: openRules
          .map((r) => `${r.firewallId}:${r.protocol}:${r.ports}:${r.source}`)
          .sort()
          .join("|"),
      });
    }

    return findings;
  },
};
