import { externalId } from "../../normalize/resource";
import type { DoLoadBalancer } from "../../do/types";
import type { Severity } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * A managed TLS certificate that has expired, is about to, or failed to issue.
 *
 * This is an availability-and-trust finding, not a reachability one, and the text is
 * careful about what it does and does not claim. An expired certificate breaks TLS for
 * clients that validate it; it does **not**, on its own, prove a man-in-the-middle. So the
 * finding never asserts interception -- it reports the lapse and escalates only when the
 * certificate is *actively bound to a public load-balancer endpoint*, where the lapse is
 * user-visible and service-affecting rather than latent.
 *
 * Let's Encrypt certificates auto-renew (DigitalOcean renews well before expiry), so a
 * healthy Let's Encrypt certificate nearing `not_after` is normal and is not reported; only
 * one that has actually expired or is in an error state indicates renewal is failing.
 */

const DAY_MS = 86_400_000;
const EXPIRY_WINDOW_DAYS = 30;

function boundPublicLoadBalancers(certId: string, loadBalancers: readonly DoLoadBalancer[]): DoLoadBalancer[] {
  return loadBalancers.filter((lb) => {
    const network = lb.network?.toUpperCase();
    const isPublic = network === "EXTERNAL" || (network !== "INTERNAL" && Boolean(lb.ip));
    if (!isPublic) return false;
    return (lb.forwarding_rules ?? []).some((rule) => rule.certificate_id === certId);
  });
}

export const certificateExpiringRule: ExposureRule = {
  kind: "certificate.expiring",
  // Reads certificates, and load balancers to decide whether a cert is bound to a public
  // endpoint (the escalation), so both must be authoritative.
  requires: ["certificates", "load_balancers"],
  references: ["https://docs.digitalocean.com/products/networking/certificates/"],
  evaluate({ inventory, now }) {
    const findings: DraftFinding[] = [];
    const nowMs = now.getTime();

    for (const cert of inventory.certificates) {
      const notAfter = cert.not_after ? new Date(cert.not_after) : null;
      const hasValidDate = notAfter !== null && !Number.isNaN(notAfter.getTime());

      const expired = hasValidDate && notAfter.getTime() <= nowMs;
      const daysLeft = hasValidDate ? (notAfter.getTime() - nowMs) / DAY_MS : Infinity;
      const isLetsEncrypt = cert.type === "lets_encrypt";
      const errored = cert.state === "error";

      // Healthy auto-renewing certificate approaching expiry: nothing to report.
      if (isLetsEncrypt && !expired && !errored) continue;

      const boundLbs = boundPublicLoadBalancers(cert.id, inventory.loadBalancers);
      const bound = boundLbs.length > 0;

      let severity: Severity;
      let situation: string;
      if (expired) {
        severity = bound ? "high" : "medium";
        situation = `expired on ${cert.not_after}`;
      } else if (errored) {
        severity = bound ? "high" : "medium";
        situation = "is in an error state, so issuance or renewal has failed";
      } else if (hasValidDate && daysLeft <= EXPIRY_WINDOW_DAYS) {
        severity = bound ? "medium" : "low";
        situation = `expires on ${cert.not_after}, within ${EXPIRY_WINDOW_DAYS} days`;
      } else {
        continue; // valid, not near expiry, not errored
      }

      const name = cert.name ?? cert.id;
      const boundNote = bound
        ? ` It is bound to public load balancer(s) ${boundLbs.map((lb) => lb.name).join(", ")}, ` +
          `so clients hitting that endpoint see the TLS failure directly.`
        : " It is not bound to any public load-balancer endpoint in this inventory, so the impact " +
          "is latent until it is put in front of traffic.";

      findings.push({
        resourceExternalId: externalId("certificate", cert.id),
        kind: "certificate.expiring",
        severity,
        confidence: "provider_reported",
        provesInternetExposure: false,
        title: expired
          ? "TLS certificate has expired"
          : errored
            ? "TLS certificate is in an error state"
            : "TLS certificate is expiring soon",
        summary:
          `Certificate "${name}" ${situation}.` +
          boundNote +
          " An expired or failed certificate breaks TLS for clients that validate it; it does" +
          " not by itself prove interception.",
        evidence: {
          confidence: "provider_reported",
          severityRationale: {
            base: severity,
            modifiers: [],
            final: severity,
            formula: `certificate ${situation}${bound ? ", bound to a public endpoint" : ", not bound"} ⇒ ${severity}`,
          },
          notAfter: cert.not_after ?? null,
          type: cert.type ?? null,
          state: cert.state ?? null,
          boundToPublicLoadBalancers: boundLbs.map((lb) => lb.id),
          dnsNames: cert.dns_names ?? [],
        },
        remediation: isLetsEncrypt
          ? "This Let's Encrypt certificate did not auto-renew. Check the domain's DNS and " +
            "validation records, then re-issue or replace it in the DigitalOcean control panel."
          : "Renew or replace the certificate before it lapses and rebind the load-balancer " +
            "listener to the new certificate. Automate renewal so this does not recur.",
        stableElement: "certificate-expiry",
        // Depends on the certificate listing, and on load balancers to decide binding, so it
        // reconciles only when both were authoritative.
        coverageKeys: ["certificates", "load_balancers"],
      });
    }

    return findings;
  },
};
