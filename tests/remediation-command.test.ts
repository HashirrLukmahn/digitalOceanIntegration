import { describe, expect, it } from "vitest";
import { remediationCommand } from "../src/exposure/remediation-command";

describe("templated remediation", () => {
  it("builds a firewall removal from the offending rule", () => {
    const out = remediationCommand("droplet.public_ingress", "do:droplet:595135351", {
      openRules: [
        { firewallId: "fw-1", protocol: "tcp", ports: "22", source: "0.0.0.0/0" },
        { firewallId: "fw-1", protocol: "tcp", ports: "443", source: "0.0.0.0/0" },
      ],
    });

    expect(out?.command).toContain("doctl compute firewall remove-rules fw-1");
    expect(out?.command).toContain("ports:22,address:0.0.0.0/0");
    expect(out?.command).toContain("ports:443,address:0.0.0.0/0");
  });

  it("strips the URN prefix so the command carries the provider id", () => {
    const out = remediationCommand("database.trusted_source_is_public", "do:dbaas:abc-123", {
      publicTrustedSources: [{ type: "ip_addr", value: "rule-uuid" }],
    });
    expect(out?.command).toContain("doctl databases firewalls remove abc-123");
    expect(out?.command).not.toContain("do:dbaas:");
  });

  it("returns nothing when the evidence lacks what the command needs", () => {
    expect(remediationCommand("droplet.public_ingress", "do:droplet:1", {})).toBeNull();
    expect(
      remediationCommand("database.trusted_source_is_public", "do:dbaas:x", {
        publicTrustedSources: [],
      }),
    ).toBeNull();
  });

  it.each([
    "droplet.no_firewall",
    "load_balancer.public_frontend",
    "app.public_ingress",
    "app.plaintext_secret_env",
    "space.public_read",
  ])("emits no command for %s, where the fix depends on the operator", (kind) => {
    // A wrong command pasted into a production shell is worse than prose.
    expect(remediationCommand(kind, "do:droplet:1", {})).toBeNull();
  });
});
