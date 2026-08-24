import { describe, expect, it } from "vitest";
import { emptyInventory, type RawInventory } from "../src/do/collectors";
import { evaluateExposure } from "../src/exposure/engine";
import { describePorts, isPublicInternetCidr, parsePorts } from "../src/exposure/ports";
import { calibrateSeverity } from "../src/exposure/severity";
import { buildContext, fingerprint, indexFirewallsByDroplet } from "../src/exposure/types";
import { dropletNoFirewallRule, dropletOpenIngressRule } from "../src/exposure/rules/droplet";
import {
  databasePublicNoTrustedSourcesRule,
  databaseTrustedSourceIsPublicRule,
} from "../src/exposure/rules/database";
import {
  appPublicIngressRule,
  kubernetesPublicEndpointRule,
  loadBalancerPublicRule,
} from "../src/exposure/rules/network";

const ACCOUNT = "acct-1";

function inventory(overrides: Partial<RawInventory>): RawInventory {
  return { ...emptyInventory(), ...overrides };
}

const run = (rule: { evaluate: ReturnType<typeof Object> }, inv: RawInventory) =>
  (rule as { evaluate: (c: ReturnType<typeof buildContext>) => unknown[] }).evaluate(
    buildContext(inv),
  );

const publicDroplet = (over: Record<string, unknown> = {}) => ({
  id: 1,
  name: "web-01",
  status: "active",
  networks: { v4: [{ ip_address: "203.0.113.10", type: "public" }] },
  ...over,
});

const privateDroplet = {
  id: 2,
  name: "internal",
  networks: { v4: [{ ip_address: "10.0.0.5", type: "private" }] },
};

// --------------------------------------------------------------------------------

describe("port parsing", () => {
  it('treats "0" as every port, not port zero', () => {
    // The single most consequential parsing detail in the whole rule set.
    expect(parsePorts("0")).toEqual({ from: 0, to: 65535, all: true });
    expect(describePorts(parsePorts("0"), "tcp")).toBe("all TCP ports");
  });

  it("parses a single port", () => {
    expect(parsePorts("22")).toEqual({ from: 22, to: 22, all: false });
  });

  it("parses a range and normalises reversed bounds", () => {
    expect(parsePorts("8000-9000")).toEqual({ from: 8000, to: 9000, all: false });
    expect(parsePorts("9000-8000")).toEqual({ from: 8000, to: 9000, all: false });
  });

  it("falls back to the widest reading for unparseable input", () => {
    expect(parsePorts("nonsense").all).toBe(true);
    expect(parsePorts(undefined).all).toBe(true);
  });
});

describe("public internet CIDR detection", () => {
  it("recognises the two universal CIDRs", () => {
    expect(isPublicInternetCidr("0.0.0.0/0")).toBe(true);
    expect(isPublicInternetCidr("::/0")).toBe(true);
  });

  it("does not treat merely broad ranges as universal", () => {
    // Strict on purpose: every finding must survive "prove it".
    expect(isPublicInternetCidr("0.0.0.0/1")).toBe(false);
    expect(isPublicInternetCidr("10.0.0.0/8")).toBe(false);
  });
});

describe("severity calibration", () => {
  it("scores a public web service low rather than critical", () => {
    expect(calibrateSeverity("none", "web_ports")).toBe("low");
  });

  it("scores an internet-facing datastore critical", () => {
    expect(calibrateSeverity("datastore", "sensitive_ports")).toBe("critical");
  });

  it("scales with sensitivity for the same reachability", () => {
    expect(calibrateSeverity("none", "all_ports")).toBe("high");
    expect(calibrateSeverity("datastore", "all_ports")).toBe("critical");
  });
});

// --------------------------------------------------------------------------------

describe("rule: droplet has no firewall", () => {
  it("fires for a public droplet with no firewall", () => {
    const findings = run(dropletNoFirewallRule, inventory({ droplets: [publicDroplet()] }));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ kind: "droplet.no_firewall", severity: "high" });
  });

  it("does not fire for a droplet with only a private address", () => {
    expect(run(dropletNoFirewallRule, inventory({ droplets: [privateDroplet] }))).toHaveLength(0);
  });

  it("does not fire when a firewall is attached by droplet id", () => {
    const findings = run(
      dropletNoFirewallRule,
      inventory({
        droplets: [publicDroplet()],
        firewalls: [{ id: "fw", name: "web", droplet_ids: [1], inbound_rules: [] }],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not fire when a firewall is attached by tag", () => {
    // Tag attachment is real in DigitalOcean. Missing it would report correctly
    // firewalled droplets as naked -- a false positive that destroys trust fast.
    const findings = run(
      dropletNoFirewallRule,
      inventory({
        droplets: [publicDroplet({ tags: ["web"] })],
        firewalls: [{ id: "fw", name: "by-tag", tags: ["web"], inbound_rules: [] }],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("records that tag attachment was considered", () => {
    const [finding] = run(dropletNoFirewallRule, inventory({ droplets: [publicDroplet()] })) as Array<{
      evidence: Record<string, unknown>;
    }>;
    expect(finding!.evidence.checkedAttachmentMethods).toEqual([
      "firewall.droplet_ids",
      "firewall.tags",
    ]);
  });
});

describe("rule: droplet accepts internet ingress", () => {
  const withRule = (ports: string, protocol = "tcp") =>
    inventory({
      droplets: [publicDroplet()],
      firewalls: [
        {
          id: "fw",
          name: "open",
          droplet_ids: [1],
          inbound_rules: [{ protocol, ports, sources: { addresses: ["0.0.0.0/0"] } }],
        },
      ],
    });

  it("fires and names the service when SSH is world-open", () => {
    const [finding] = run(dropletOpenIngressRule, withRule("22")) as Array<{
      kind: string;
      severity: string;
      title: string;
    }>;
    expect(finding).toMatchObject({ kind: "droplet.public_ingress", severity: "high" });
    expect(finding!.title).toContain("SSH");
  });

  it('treats ports "0" as every port and flags the sensitive services inside it', () => {
    const [finding] = run(dropletOpenIngressRule, withRule("0")) as Array<{
      severity: string;
      evidence: { openRules: Array<{ portsMeaning: string; sensitiveServices: unknown[] }> };
    }>;
    expect(finding!.severity).toBe("high");
    expect(finding!.evidence.openRules[0]!.portsMeaning).toBe("all TCP ports");
    expect(finding!.evidence.openRules[0]!.sensitiveServices.length).toBeGreaterThan(0);
  });

  it("scores a world-open HTTPS port low", () => {
    const [finding] = run(dropletOpenIngressRule, withRule("443")) as Array<{ severity: string }>;
    expect(finding!.severity).toBe("low");
  });

  it("does not fire when the source is a specific range", () => {
    const findings = run(
      dropletOpenIngressRule,
      inventory({
        droplets: [publicDroplet()],
        firewalls: [
          {
            id: "fw",
            name: "scoped",
            droplet_ids: [1],
            inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["203.0.113.0/24"] } }],
          },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not fire for a private droplet however open the firewall is", () => {
    const findings = run(
      dropletOpenIngressRule,
      inventory({
        droplets: [privateDroplet],
        firewalls: [
          {
            id: "fw",
            name: "open",
            droplet_ids: [2],
            inbound_rules: [{ protocol: "tcp", ports: "0", sources: { addresses: ["0.0.0.0/0"] } }],
          },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("emits one finding per droplet, not one per firewall rule", () => {
    // The specification is explicit: a row is an actionable exposure, not a raw rule.
    const findings = run(
      dropletOpenIngressRule,
      inventory({
        droplets: [publicDroplet()],
        firewalls: [
          {
            id: "fw",
            name: "open",
            droplet_ids: [1],
            inbound_rules: [
              { protocol: "tcp", ports: "22", sources: { addresses: ["0.0.0.0/0"] } },
              { protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0"] } },
              { protocol: "tcp", ports: "3306", sources: { addresses: ["0.0.0.0/0"] } },
            ],
          },
        ],
      }),
    ) as Array<{ evidence: { openRules: unknown[] } }>;

    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence.openRules).toHaveLength(3);
  });

  it("takes severity from the worst rule, not the average", () => {
    const findings = run(
      dropletOpenIngressRule,
      inventory({
        droplets: [publicDroplet()],
        firewalls: [
          {
            id: "fw",
            name: "mixed",
            droplet_ids: [1],
            inbound_rules: [
              { protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0"] } },
              { protocol: "tcp", ports: "5432", sources: { addresses: ["0.0.0.0/0"] } },
            ],
          },
        ],
      }),
    ) as Array<{ severity: string }>;
    expect(findings[0]!.severity).toBe("high");
  });

  it("detects IPv6 wildcard sources", () => {
    const findings = run(
      dropletOpenIngressRule,
      inventory({
        droplets: [publicDroplet()],
        firewalls: [
          {
            id: "fw",
            name: "v6",
            droplet_ids: [1],
            inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["::/0"] } }],
          },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
  });
});

describe("rule: load balancer public frontend", () => {
  it("fires for an EXTERNAL load balancer", () => {
    const findings = run(
      loadBalancerPublicRule,
      inventory({
        loadBalancers: [
          {
            id: "lb",
            name: "public-lb",
            network: "EXTERNAL",
            ip: "203.0.113.50",
            forwarding_rules: [{ entry_port: 443, entry_protocol: "https" }],
          },
        ],
      }),
    ) as Array<{ severity: string; evidence: { determinedBy: string } }>;

    expect(findings).toHaveLength(1);
    // Public HTTPS is the point of a load balancer -- recorded, not alarmed about.
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.evidence.determinedBy).toBe("network=EXTERNAL");
  });

  it("does not fire for an INTERNAL load balancer even if an IP is present", () => {
    const findings = run(
      loadBalancerPublicRule,
      inventory({ loadBalancers: [{ id: "lb", name: "internal", network: "INTERNAL", ip: "10.0.0.9" }] }),
    );
    expect(findings).toHaveLength(0);
  });

  it("raises severity when a sensitive port is forwarded", () => {
    const findings = run(
      loadBalancerPublicRule,
      inventory({
        loadBalancers: [
          {
            id: "lb",
            name: "db-lb",
            network: "EXTERNAL",
            ip: "203.0.113.51",
            forwarding_rules: [{ entry_port: 5432, entry_protocol: "tcp" }],
          },
        ],
      }),
    ) as Array<{ severity: string }>;
    expect(findings[0]!.severity).toBe("high");
  });
});

describe("rule: managed database exposure", () => {
  const cluster = {
    id: "db-1",
    name: "prod-pg",
    engine: "pg",
    connection: { host: "prod-pg.db.ondigitalocean.com", port: 25060 },
  };

  it("fires when a public cluster has an empty trusted-source list", () => {
    const findings = run(
      databasePublicNoTrustedSourcesRule,
      inventory({ databases: [cluster], databaseFirewalls: { "db-1": [] } }),
    ) as Array<{ severity: string }>;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
  });

  it("does NOT fire when trusted sources could not be fetched", () => {
    // Absent means unknown. Guessing here would report a locked-down database as
    // world-readable on the strength of a transient API failure.
    const findings = run(
      databasePublicNoTrustedSourcesRule,
      inventory({ databases: [cluster], databaseFirewalls: {} }),
    );
    expect(findings).toHaveLength(0);
  });

  it("does not fire when trusted sources exist", () => {
    const findings = run(
      databasePublicNoTrustedSourcesRule,
      inventory({
        databases: [cluster],
        databaseFirewalls: { "db-1": [{ type: "droplet", value: "1" }] },
      }),
    );
    expect(findings).toHaveLength(0);
  });

  it("fires when a trusted source is 0.0.0.0/0", () => {
    const findings = run(
      databaseTrustedSourceIsPublicRule,
      inventory({
        databases: [cluster],
        databaseFirewalls: { "db-1": [{ type: "ip_addr", value: "0.0.0.0/0" }] },
      }),
    ) as Array<{ severity: string }>;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
  });

  it("does not treat a specific trusted IP as public", () => {
    const findings = run(
      databaseTrustedSourceIsPublicRule,
      inventory({
        databases: [cluster],
        databaseFirewalls: { "db-1": [{ type: "ip_addr", value: "203.0.113.7" }] },
      }),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("rule: kubernetes control plane", () => {
  const cluster = { id: "k8s-1", name: "prod", endpoint: "https://k8s-1.k8s.ondigitalocean.com" };

  it("does NOT fire when control_plane_firewall is null", () => {
    // Nullable and invite-only early availability: null means "cannot tell". Treating
    // it as unrestricted would flag essentially every cluster in existence.
    expect(
      run(kubernetesPublicEndpointRule, inventory({ kubernetes: [{ ...cluster, control_plane_firewall: null }] })),
    ).toHaveLength(0);
    expect(run(kubernetesPublicEndpointRule, inventory({ kubernetes: [cluster] }))).toHaveLength(0);
  });

  it("fires when the control-plane firewall is explicitly disabled", () => {
    const findings = run(
      kubernetesPublicEndpointRule,
      inventory({ kubernetes: [{ ...cluster, control_plane_firewall: { enabled: false } }] }),
    ) as Array<{ severity: string; evidence: { determinedBy: string } }>;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("medium");
    expect(findings[0]!.evidence.determinedBy).toBe("control_plane_firewall.enabled=false");
  });

  it("fires when the allowlist admits the whole internet", () => {
    const findings = run(
      kubernetesPublicEndpointRule,
      inventory({
        kubernetes: [
          { ...cluster, control_plane_firewall: { enabled: true, allowed_addresses: ["0.0.0.0/0"] } },
        ],
      }),
    );
    expect(findings).toHaveLength(1);
  });

  it("does not fire for a genuinely restricted allowlist", () => {
    const findings = run(
      kubernetesPublicEndpointRule,
      inventory({
        kubernetes: [
          {
            ...cluster,
            control_plane_firewall: { enabled: true, allowed_addresses: ["203.0.113.0/24"] },
          },
        ],
      }),
    );
    expect(findings).toHaveLength(0);
  });
});

describe("rule: app platform ingress", () => {
  it("records a public app at low severity", () => {
    const findings = run(
      appPublicIngressRule,
      inventory({ apps: [{ id: "app-1", spec: { name: "store" }, live_url: "https://store.example" }] }),
    ) as Array<{ severity: string }>;
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("low");
  });

  it("does not fire for an app with no ingress", () => {
    expect(run(appPublicIngressRule, inventory({ apps: [{ id: "app-2" }] }))).toHaveLength(0);
  });
});

// --------------------------------------------------------------------------------

describe("firewall indexing", () => {
  it("resolves attachment by id and by tag together", () => {
    const index = indexFirewallsByDroplet(
      [{ id: 1, name: "a", tags: ["web"] }, { id: 2, name: "b" }],
      [
        { id: "by-id", name: "by-id", droplet_ids: [2] },
        { id: "by-tag", name: "by-tag", tags: ["web"] },
      ],
    );
    expect(index.get(1)!.map((f) => f.id)).toEqual(["by-tag"]);
    expect(index.get(2)!.map((f) => f.id)).toEqual(["by-id"]);
  });
});

describe("fingerprint stability", () => {
  const draft = {
    resourceExternalId: "do:droplet:1",
    kind: "droplet.public_ingress",
    severity: "high" as const,
    title: "t",
    summary: "s",
    evidence: {},
    remediation: "r",
    stableElement: "fw:tcp:22:0.0.0.0/0",
  };

  it("is identical for an unchanged configuration", () => {
    expect(fingerprint(ACCOUNT, draft)).toBe(fingerprint(ACCOUNT, draft));
  });

  it("ignores fields that are not part of the identity", () => {
    // Retitling or rewording a finding must not orphan its history.
    expect(fingerprint(ACCOUNT, { ...draft, title: "different", summary: "reworded" })).toBe(
      fingerprint(ACCOUNT, draft),
    );
  });

  it("changes when the offending configuration changes", () => {
    expect(fingerprint(ACCOUNT, { ...draft, stableElement: "fw:tcp:443:0.0.0.0/0" })).not.toBe(
      fingerprint(ACCOUNT, draft),
    );
  });

  it("differs across accounts and across resources", () => {
    expect(fingerprint("other", draft)).not.toBe(fingerprint(ACCOUNT, draft));
    expect(fingerprint(ACCOUNT, { ...draft, resourceExternalId: "do:droplet:2" })).not.toBe(
      fingerprint(ACCOUNT, draft),
    );
  });
});

describe("engine", () => {
  it("returns findings sorted by severity and marks exposed resources", () => {
    const result = evaluateExposure(
      ACCOUNT,
      inventory({
        droplets: [publicDroplet()],
        databases: [{ id: "db-1", name: "pg", connection: { host: "h", port: 25060 } }],
        databaseFirewalls: { "db-1": [] },
        apps: [{ id: "app-1", live_url: "https://x.example" }],
      }),
    );

    expect(result.findings[0]!.severity).toBe("critical");
    expect(result.findings.at(-1)!.severity).toBe("low");
    expect(result.exposedResourceIds.has("do:dbaas:db-1")).toBe(true);
    expect(result.exposedResourceIds.has("do:droplet:1")).toBe(true);
  });

  it("produces no findings for an empty account", () => {
    const result = evaluateExposure(ACCOUNT, emptyInventory());
    expect(result.findings).toEqual([]);
    expect(result.exposedResourceIds.size).toBe(0);
  });

  it("assigns every finding a unique id", () => {
    const result = evaluateExposure(
      ACCOUNT,
      inventory({
        droplets: [publicDroplet(), publicDroplet({ id: 3, name: "web-02" })],
      }),
    );
    expect(new Set(result.findings.map((f) => f.id)).size).toBe(result.findings.length);
  });
});
