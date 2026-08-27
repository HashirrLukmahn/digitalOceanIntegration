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
  databaseVersionEndOfLifeRule,
} from "../src/exposure/rules/database";
import {
  appPublicIngressRule,
  kubernetesPublicEndpointRule,
  loadBalancerPublicRule,
  loadBalancerSensitiveBackendPortRule,
} from "../src/exposure/rules/network";
import { backendPortReachability } from "../src/exposure/effective-policy";
import {
  dnsRecordToUnassignedReservedIpRule,
  reservedIpUnassignedRule,
} from "../src/exposure/rules/dns";
import {
  kubernetesAutoUpgradeDisabledRule,
  kubernetesUpgradeAvailableRule,
} from "../src/exposure/rules/kubernetes";
import { certificateExpiringRule } from "../src/exposure/rules/certificate";

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
    confidence: "provider_reported" as const,
    provesInternetExposure: true,
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

describe("database version lifecycle", () => {
  const NOW = new Date("2026-08-26T00:00:00.000Z");
  const evalWith = (cluster: Record<string, unknown>) =>
    databaseVersionEndOfLifeRule.evaluate(buildContext(inventory({ databases: [cluster as never] }), NOW));

  it("flags a past end-of-life version as high, without marking it internet-exposed", () => {
    const [finding] = evalWith({
      id: "db-1",
      name: "pg",
      engine: "pg",
      version: "11",
      version_end_of_life: "2024-11-09",
    });
    expect(finding!.severity).toBe("high");
    expect(finding!.confidence).toBe("provider_reported");
    expect(finding!.provesInternetExposure).toBe(false);
    expect(finding!.coverageKeys).toEqual(["databases"]);
  });

  it("flags an end-of-life within 90 days as medium", () => {
    const [finding] = evalWith({
      id: "db-2",
      name: "mysql",
      engine: "mysql",
      version: "8",
      version_end_of_life: "2026-10-01", // ~36 days out
    });
    expect(finding!.severity).toBe("medium");
  });

  it("treats end-of-availability with a future end-of-life as low", () => {
    const [finding] = evalWith({
      id: "db-3",
      name: "pg",
      engine: "pg",
      version: "13",
      version_end_of_availability: "2026-01-01", // past
      version_end_of_life: "2027-11-09", // comfortably future
    });
    expect(finding!.severity).toBe("low");
  });

  it("says nothing when the lifecycle dates are comfortably in the future", () => {
    expect(
      evalWith({ id: "db-4", name: "pg", version_end_of_life: "2029-01-01" }),
    ).toEqual([]);
  });

  it("says nothing when the provider reports no lifecycle dates", () => {
    expect(evalWith({ id: "db-5", name: "pg", engine: "pg", version: "16" })).toEqual([]);
  });
});

describe("kubernetes auto-upgrade posture", () => {
  const evalWith = (cluster: Record<string, unknown>) =>
    kubernetesAutoUpgradeDisabledRule.evaluate(buildContext(inventory({ kubernetes: [cluster as never] })));

  it("fires only when auto_upgrade is explicitly false", () => {
    const [finding] = evalWith({ id: "k1", name: "prod", auto_upgrade: false });
    expect(finding!.kind).toBe("kubernetes.auto_upgrade_disabled");
    expect(finding!.severity).toBe("low");
    expect(finding!.provesInternetExposure).toBe(false);
  });

  it("stays silent when auto_upgrade is enabled", () => {
    expect(evalWith({ id: "k2", name: "prod", auto_upgrade: true })).toEqual([]);
  });

  it("treats an absent auto_upgrade as unknown, not disabled", () => {
    expect(evalWith({ id: "k3", name: "prod" })).toEqual([]);
  });
});

describe("kubernetes available upgrades", () => {
  const evalWith = (cluster: Record<string, unknown>, upgrades: Record<string, unknown[]>) =>
    kubernetesUpgradeAvailableRule.evaluate(
      buildContext(
        inventory({ kubernetes: [cluster as never], kubernetesUpgrades: upgrades as never }),
      ),
    );

  it("flags a patch upgrade as the security-relevant case, without claiming unsupported", () => {
    const [finding] = evalWith(
      { id: "k1", name: "prod", version: "1.31.1-do.0" },
      { k1: [{ kubernetes_version: "1.31.3-do.0" }] },
    );
    expect(finding!.kind).toBe("kubernetes.upgrade_available");
    expect(finding!.severity).toBe("low");
    expect(finding!.provesInternetExposure).toBe(false);
    expect((finding!.evidence as { patchUpgradeAvailable: boolean }).patchUpgradeAvailable).toBe(true);
    // Explicitly disclaims the unsupported/EOL claim rather than making it.
    expect(finding!.summary).toMatch(/does not mean the installed version is unsupported/i);
    expect(finding!.coverageKeys).toEqual(["kubernetes", "kubernetes_upgrades:k1"]);
  });

  it("distinguishes a minor-only upgrade from a patch upgrade", () => {
    const [finding] = evalWith(
      { id: "k2", name: "prod", version: "1.31.3-do.0" },
      { k2: [{ kubernetes_version: "1.32.0-do.0" }] },
    );
    expect((finding!.evidence as { patchUpgradeAvailable: boolean }).patchUpgradeAvailable).toBe(false);
  });

  it("says nothing when the provider reports the cluster is up to date", () => {
    expect(evalWith({ id: "k3", name: "prod", version: "1.31.3-do.0" }, { k3: [] })).toEqual([]);
  });

  it("treats an unfetched upgrades listing as unknown, not up to date", () => {
    // No entry for this cluster id -> the child call was not made or failed.
    expect(evalWith({ id: "k4", name: "prod", version: "1.31.1-do.0" }, {})).toEqual([]);
  });
});

describe("certificate expiry", () => {
  const NOW = new Date("2026-08-26T00:00:00.000Z");
  const publicLbWithCert = (certId: string) => ({
    id: "lb-1",
    name: "edge",
    network: "EXTERNAL",
    ip: "203.0.113.5",
    forwarding_rules: [{ entry_protocol: "https", entry_port: 443, certificate_id: certId }],
  });
  const evalWith = (certs: Record<string, unknown>[], loadBalancers: Record<string, unknown>[] = []) =>
    certificateExpiringRule.evaluate(
      buildContext(inventory({ certificates: certs as never, loadBalancers: loadBalancers as never }), NOW),
    );

  it("escalates an expired certificate bound to a public endpoint to high", () => {
    const [finding] = evalWith(
      [{ id: "c1", name: "edge", type: "custom", state: "verified", not_after: "2025-01-01T00:00:00Z" }],
      [publicLbWithCert("c1")],
    );
    expect(finding!.severity).toBe("high");
    expect(finding!.provesInternetExposure).toBe(false);
    expect(finding!.coverageKeys).toEqual(["certificates", "load_balancers"]);
    // Explicitly disclaims interception rather than claiming a MITM.
    expect(finding!.summary).toMatch(/not by itself prove interception/i);
  });

  it("reports an expired but unbound certificate at a lower severity", () => {
    const [finding] = evalWith([
      { id: "c2", name: "orphan", type: "custom", state: "verified", not_after: "2025-01-01T00:00:00Z" },
    ]);
    expect(finding!.severity).toBe("medium");
  });

  it("flags a custom certificate expiring within the window as low when unbound", () => {
    const [finding] = evalWith([
      { id: "c3", name: "soon", type: "custom", state: "verified", not_after: "2026-09-10T00:00:00Z" },
    ]);
    expect(finding!.severity).toBe("low");
  });

  it("stays silent for a healthy auto-renewing Let's Encrypt certificate near expiry", () => {
    expect(
      evalWith([{ id: "c4", type: "lets_encrypt", state: "verified", not_after: "2026-09-01T00:00:00Z" }]),
    ).toEqual([]);
  });

  it("still flags a Let's Encrypt certificate that has actually expired or errored", () => {
    expect(
      evalWith([{ id: "c5", type: "lets_encrypt", state: "verified", not_after: "2025-01-01T00:00:00Z" }]),
    ).toHaveLength(1);
    expect(
      evalWith([{ id: "c6", type: "lets_encrypt", state: "error", not_after: "2030-01-01T00:00:00Z" }]),
    ).toHaveLength(1);
  });

  it("says nothing about a healthy custom certificate far from expiry", () => {
    expect(
      evalWith([{ id: "c7", type: "custom", state: "verified", not_after: "2030-01-01T00:00:00Z" }]),
    ).toEqual([]);
  });
});

describe("effective firewall policy", () => {
  const tcp = (ports: string, sources: Record<string, unknown>) => ({ protocol: "tcp", ports, sources });

  it("reports load_balancer when a covering rule names the LB uid", () => {
    const fw = { id: "f", name: "f", inbound_rules: [tcp("5432", { load_balancer_uids: ["lb-x"] })] };
    expect(backendPortReachability([fw as never], 5432, "lb-x")).toBe("load_balancer");
  });

  it("reports public when a covering rule admits the whole internet", () => {
    const fw = { id: "f", name: "f", inbound_rules: [tcp("5432", { addresses: ["0.0.0.0/0"] })] };
    expect(backendPortReachability([fw as never], 5432, "lb-x")).toBe("public");
  });

  it("returns null when no covering rule admits the port", () => {
    const fw = { id: "f", name: "f", inbound_rules: [tcp("443", { load_balancer_uids: ["lb-x"] })] };
    expect(backendPortReachability([fw as never], 5432, "lb-x")).toBe(null);
  });

  it("ignores a UDP rule on the same number", () => {
    const fw = { id: "f", name: "f", inbound_rules: [{ protocol: "udp", ports: "5432", sources: { load_balancer_uids: ["lb-x"] } }] };
    expect(backendPortReachability([fw as never], 5432, "lb-x")).toBe(null);
  });
});

describe("load balancer sensitive backend port", () => {
  const backend = {
    id: 501,
    name: "db-node",
    networks: { v4: [{ ip_address: "10.0.0.9", type: "private" }] },
    tags: ["db"],
  };
  const publicLb = (over: Record<string, unknown> = {}) => ({
    id: "lb-x",
    name: "edge",
    network: "EXTERNAL",
    ip: "203.0.113.9",
    droplet_ids: [501],
    forwarding_rules: [{ entry_protocol: "tcp", entry_port: 5432, target_protocol: "tcp", target_port: 5432 }],
    ...over,
  });
  const fwTrustingLb = {
    id: "fw-db",
    name: "db-fw",
    droplet_ids: [501],
    inbound_rules: [{ protocol: "tcp", ports: "5432", sources: { load_balancer_uids: ["lb-x"] } }],
  };
  const run = (inv: Record<string, unknown>) =>
    loadBalancerSensitiveBackendPortRule.evaluate(buildContext(inventory(inv as never)));

  it("fires when the LB, forwarding rule, and backend firewall collectively open the path", () => {
    const [finding] = run({ droplets: [backend], firewalls: [fwTrustingLb], loadBalancers: [publicLb()] });
    expect(finding!.kind).toBe("load_balancer.sensitive_backend_port");
    expect(finding!.severity).toBe("high");
    expect(finding!.confidence).toBe("derived");
    expect(finding!.provesInternetExposure).toBe(true);
    expect(finding!.coverageKeys).toEqual(["load_balancers", "droplets", "firewalls"]);
    expect(finding!.resourceExternalId).toBe("do:loadbalancer:lb-x");
  });

  it("does NOT fire when the backend firewall blocks the target port (path incomplete)", () => {
    const blocking = { ...fwTrustingLb, inbound_rules: [{ protocol: "tcp", ports: "443", sources: { load_balancer_uids: ["lb-x"] } }] };
    expect(run({ droplets: [backend], firewalls: [blocking], loadBalancers: [publicLb()] })).toEqual([]);
  });

  it("does not fire for a forwarding rule to an ordinary web port", () => {
    const webLb = publicLb({
      forwarding_rules: [{ entry_protocol: "https", entry_port: 443, target_protocol: "http", target_port: 80 }],
    });
    const webFw = { ...fwTrustingLb, inbound_rules: [{ protocol: "tcp", ports: "80", sources: { load_balancer_uids: ["lb-x"] } }] };
    expect(run({ droplets: [backend], firewalls: [webFw], loadBalancers: [webLb] })).toEqual([]);
  });

  it("does not fire for an internal load balancer", () => {
    const internal = publicLb({ network: "INTERNAL" });
    expect(run({ droplets: [backend], firewalls: [fwTrustingLb], loadBalancers: [internal] })).toEqual([]);
  });

  it("resolves tag-selected backends, not just explicit droplet ids", () => {
    const taggedLb = publicLb({ droplet_ids: [], tag: "db" });
    const [finding] = run({ droplets: [backend], firewalls: [fwTrustingLb], loadBalancers: [taggedLb] });
    expect(finding).toBeDefined();
  });

  it("integrates through the engine and marks the load balancer internet-exposed", () => {
    const result = evaluateExposure(
      ACCOUNT,
      inventory({ droplets: [backend as never], firewalls: [fwTrustingLb as never], loadBalancers: [publicLb() as never] }),
    );
    expect(result.findings.some((f) => f.kind === "load_balancer.sensitive_backend_port")).toBe(true);
    expect(result.exposedResourceIds.has("do:loadbalancer:lb-x")).toBe(true);
  });
});

describe("path: public workload to datastore", () => {
  // A public droplet with SSH open to the world...
  const publicOpenDroplet = {
    id: 700,
    name: "app-01",
    networks: { v4: [{ ip_address: "203.0.113.70", type: "public" }] },
    tags: ["app"],
  };
  const openFirewall = {
    id: "fw-open",
    name: "open",
    droplet_ids: [700],
    inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["0.0.0.0/0"] } }],
  };
  // ...that a database trusts as a source.
  const db = { id: "db-x", name: "orders-pg", engine: "pg", connection: { host: "h", port: 25060 } };
  const dbTrustsDroplet = { "db-x": [{ type: "droplet", value: "700" }] };

  const fullInventory = (over: Record<string, unknown> = {}) =>
    inventory({
      droplets: [publicOpenDroplet as never],
      firewalls: [openFirewall as never],
      databases: [db as never],
      databaseFirewalls: dbTrustsDroplet as never,
      ...over,
    });

  it("reports the datastore as reachable when a trusted workload is internet-exposed", () => {
    const result = evaluateExposure(ACCOUNT, fullInventory());
    const path = result.findings.find((f) => f.kind === "path.public_workload_to_datastore");
    expect(path).toBeDefined();
    expect(path!.resourceExternalId).toBe("do:dbaas:db-x");
    expect(path!.severity).toBe("high");
    expect(path!.confidence).toBe("derived");
    // The datastore's exposure is indirect, so the path does not mark it internet-exposed.
    expect(path!.provesInternetExposure).toBe(false);
    expect(result.exposedResourceIds.has("do:dbaas:db-x")).toBe(false);
    // ...but the exposed workload itself is in the set (from phase one).
    expect(result.exposedResourceIds.has("do:droplet:700")).toBe(true);
    expect(path!.coverageKeys).toEqual(
      expect.arrayContaining(["databases", "database_firewall:db-x", "digitalocean.droplet"]),
    );
  });

  it("does NOT report a path when the trusted workload is not internet-exposed", () => {
    // Same trust edge, but the droplet's firewall only admits SSH from a bastion range, so
    // phase one never marks it exposed and the path does not complete.
    const bastionFirewall = {
      ...openFirewall,
      inbound_rules: [{ protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.0/24"] } }],
    };
    const result = evaluateExposure(ACCOUNT, fullInventory({ firewalls: [bastionFirewall as never] }));
    expect(result.findings.some((f) => f.kind === "path.public_workload_to_datastore")).toBe(false);
  });

  it("does NOT treat a database that only trusts 0.0.0.0/0 as a workload path", () => {
    // A whole-internet trusted source is a direct-exposure finding, not a trust edge, so no
    // path rule fires off it.
    const result = evaluateExposure(
      ACCOUNT,
      fullInventory({ databaseFirewalls: { "db-x": [{ type: "ip_addr", value: "0.0.0.0/0" }] } as never }),
    );
    expect(result.findings.some((f) => f.kind === "path.public_workload_to_datastore")).toBe(false);
  });
});

describe("reserved IPs and stale DNS", () => {
  const unassigned = { ip: "203.0.113.250", region: { slug: "nyc3" }, droplet: null };
  const assigned = { ip: "203.0.113.240", region: { slug: "nyc3" }, droplet: { id: 5 } };

  it("flags an unassigned reserved IP as informational, but not an assigned one", () => {
    const findings = reservedIpUnassignedRule.evaluate(
      buildContext(inventory({ reservedIps: [unassigned, assigned] as never })),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.kind).toBe("netip.reserved_ip.unassigned");
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.resourceExternalId).toBe("do:reserved_ip:203.0.113.250");
    expect(findings[0]!.provesInternetExposure).toBe(false);
  });

  const dnsInventory = (records: Record<string, unknown>[], reservedIps: Record<string, unknown>[] = [unassigned]) =>
    inventory({
      reservedIps: reservedIps as never,
      domains: [{ name: "acme.example" }] as never,
      domainRecords: { "acme.example": records } as never,
    });

  it("flags a record pointing at the account's own unassigned reserved IP as a heuristic", () => {
    const [finding] = dnsRecordToUnassignedReservedIpRule.evaluate(
      buildContext(dnsInventory([{ type: "A", name: "stale", data: "203.0.113.250" }])),
    );
    expect(finding!.kind).toBe("dns.record_to_unassigned_reserved_ip");
    expect(finding!.confidence).toBe("heuristic");
    expect(finding!.severity).toBe("low");
    expect(finding!.resourceExternalId).toBe("do:domain:acme.example");
    expect(finding!.summary).toMatch(/not\s+proven takeover/i);
    expect(finding!.coverageKeys).toEqual(["reserved_ips", "domains", "dns_records:acme.example"]);
  });

  it("does NOT flag a record pointing at an external IP (external hosting is normal)", () => {
    expect(
      dnsRecordToUnassignedReservedIpRule.evaluate(
        buildContext(dnsInventory([{ type: "A", name: "cdn", data: "198.51.100.7" }])),
      ),
    ).toEqual([]);
  });

  it("does NOT flag a record pointing at an ASSIGNED reserved IP", () => {
    expect(
      dnsRecordToUnassignedReservedIpRule.evaluate(
        buildContext(dnsInventory([{ type: "A", name: "live", data: "203.0.113.240" }], [assigned])),
      ),
    ).toEqual([]);
  });

  it("ignores non-address records like CNAME", () => {
    expect(
      dnsRecordToUnassignedReservedIpRule.evaluate(
        buildContext(dnsInventory([{ type: "CNAME", name: "www", data: "203.0.113.250" }])),
      ),
    ).toEqual([]);
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

  /**
   * Confidence and exposure are required axes, not optional ones. This asserts the
   * invariant at runtime across a mix of rules -- the type system enforces it at
   * compile time, and this catches a rule that satisfies the type with `undefined`
   * smuggled through `as`.
   */
  it("gives every finding an explicit confidence and exposure verdict", () => {
    const result = evaluateExposure(
      ACCOUNT,
      inventory({
        droplets: [publicDroplet()],
        databases: [{ id: "db-1", name: "pg", connection: { host: "h", port: 25060 } }],
        databaseFirewalls: { "db-1": [] },
        apps: [
          {
            id: "app-1",
            live_url: "https://x.example",
            spec: { name: "x", envs: [{ key: "STRIPE_API_KEY", type: "GENERAL" }] },
          },
        ],
      }),
    );

    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(typeof finding.confidence).toBe("string");
      expect(typeof finding.provesInternetExposure).toBe("boolean");
    }

    // The plaintext-secret finding is a disclosure finding, not a reachability one, so it
    // must not drag its app into the internet-exposed set.
    const secretFinding = result.findings.find((f) => f.kind === "app.plaintext_secret_env");
    expect(secretFinding?.provesInternetExposure).toBe(false);
    expect(result.exposedResourceIds.has("do:app:app-1")).toBe(true); // from public_ingress, not the secret
  });
});
