import { externalId } from "../../normalize/resource";
import { deriveSeverity, severityEvidence } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * A Spaces bucket readable by anyone on the internet.
 *
 * The evidence here is unusually strong. Every other rule in this codebase infers
 * exposure from configuration -- a firewall rule, a trusted-source list, a network
 * flag. This one is a demonstration: an unauthenticated request was made and the
 * bucket returned its contents. There is no interpretation step to disagree with.
 *
 * A publicly listable object store is a datastore reachable without credentials, so
 * it lands at the top of the severity matrix. This is the finding class behind a
 * large share of real-world cloud data leaks.
 */
export const spacePublicReadRule: ExposureRule = {
  kind: "space.public_read",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const probe of inventory.spaces) {
      if (!probe.publiclyListable) continue;

      // The strongest evidence class in the codebase: an anonymous request was made and
      // succeeded, so confidence is active_probe rather than an inference.
      const derivation = deriveSeverity("datastore", "sensitive_ports");

      findings.push({
        resourceExternalId: externalId("space", probe.bucket.name),
        kind: "space.public_read",
        severity: derivation.final,
        confidence: "active_probe",
        title: "Spaces bucket is readable by anyone",
        summary:
          `Bucket "${probe.bucket.name}" in ${probe.bucket.region} returned its object listing ` +
          `to an unauthenticated request. Anyone who knows or guesses the bucket name can ` +
          `enumerate and download its contents without credentials.`,
        evidence: {
          ...severityEvidence("active_probe", derivation),
          endpoint: probe.endpoint,
          region: probe.bucket.region,
          // The proof: an anonymous request, and what it returned.
          method: "unauthenticated HTTP GET",
          httpStatus: probe.status,
          publiclyListable: true,
          note:
            "Determined by demonstration rather than by reading a configuration field: an " +
            "anonymous request succeeded. Object names and contents were not read or stored.",
        },
        remediation:
          "Set the bucket's file listing to private in the DigitalOcean control panel, and " +
          "review its objects' individual permissions -- making the bucket private does not " +
          "retract objects already set to public-read. Assume anything it held has been " +
          "downloaded and rotate any credentials or personal data found there.",
        stableElement: "anonymous-list-enabled",
      });
    }

    return findings;
  },
};
