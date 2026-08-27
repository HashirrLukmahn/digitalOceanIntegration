import { externalId } from "../../normalize/resource";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * A reserved IP the account holds but has attached to nothing.
 *
 * Informational, on purpose. An unassigned reserved IP is **not** attacker-claimable while
 * the account holds it -- so this is not an exposure. It is worth surfacing anyway: it
 * costs money, and it is the ingredient a dangling-DNS record needs (see
 * `dns.record_points_to_unassigned_reserved_ip`). Reported at `low` so it informs without
 * competing with real exposures.
 */
export const reservedIpUnassignedRule: ExposureRule = {
  kind: "netip.reserved_ip.unassigned",
  requires: ["reserved_ips"],
  references: ["https://docs.digitalocean.com/products/networking/reserved-ips/"],
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const reservedIp of inventory.reservedIps) {
      if (reservedIp.droplet && reservedIp.droplet.id) continue; // assigned

      findings.push({
        resourceExternalId: externalId("reservedIp", reservedIp.ip),
        kind: "netip.reserved_ip.unassigned",
        severity: "low",
        confidence: "provider_reported",
        provesInternetExposure: false,
        title: "Reserved IP is held but not assigned",
        summary:
          `Reserved IP ${reservedIp.ip} is allocated to the account but attached to no ` +
          `resource. It is still held by the account and is not attacker-claimable, but it ` +
          `incurs cost and becomes a dangling-DNS risk if a record points at it.`,
        evidence: {
          confidence: "provider_reported",
          severityRationale: {
            base: "low",
            modifiers: [],
            final: "low",
            formula: "reserved IP allocated but unattached ⇒ informational low",
          },
          ip: reservedIp.ip,
          region: reservedIp.region?.slug ?? null,
          assigned: false,
        },
        remediation:
          "Attach the reserved IP to a resource, or release it if it is unused. If DNS " +
          "records point at it, update or remove them first.",
        stableElement: "unassigned",
        coverageKeys: ["reserved_ips"],
      });
    }

    return findings;
  },
};

/**
 * A DNS record pointing at a reserved IP the account holds but has not assigned.
 *
 * This is the API-detectable, defensible slice of "stale DNS". It is deliberately narrow:
 * a record pointing at an arbitrary external IP is **not** flagged, because external
 * hosting is completely normal and calling it a takeover would be a false positive of
 * exactly the kind that trains people to ignore the tool. What *is* suspicious is a record
 * pointing at one of the account's *own* unassigned reserved IPs: the name resolves to
 * nothing today, and if that reserved IP is ever released it becomes claimable by another
 * tenant who then inherits the name. That is a stale/dangling-DNS setup -- reported as a
 * `heuristic` (the weakest confidence class) because it is a latent posture risk, not proven
 * exploitability, and the finding text says so.
 */
export const dnsRecordToUnassignedReservedIpRule: ExposureRule = {
  kind: "dns.record_points_to_unassigned_reserved_ip",
  requires: ["reserved_ips", "domains"],
  references: ["https://docs.digitalocean.com/products/networking/dns/"],
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    const unassignedReserved = new Set(
      inventory.reservedIps
        .filter((reservedIp) => !(reservedIp.droplet && reservedIp.droplet.id))
        .map((reservedIp) => reservedIp.ip),
    );
    if (unassignedReserved.size === 0) return findings;

    for (const [domainName, records] of Object.entries(inventory.domainRecords)) {
      const dangling = records.filter(
        (record) =>
          (record.type === "A" || record.type === "AAAA") &&
          typeof record.data === "string" &&
          unassignedReserved.has(record.data.trim()),
      );
      if (dangling.length === 0) continue;

      findings.push({
        resourceExternalId: externalId("domain", domainName),
        kind: "dns.record_points_to_unassigned_reserved_ip",
        severity: "low",
        confidence: "heuristic",
        provesInternetExposure: false,
        title: "DNS record points to an unassigned reserved IP",
        summary:
          `Zone "${domainName}" has ${dangling.length} record(s) pointing to reserved IP(s) the ` +
          `account holds but has not attached to any resource ` +
          `(${dangling.map((r) => `${r.name ?? "@"} → ${r.data}`).join(", ")}). The name resolves ` +
          `to nothing now, and if the reserved IP is ever released it becomes claimable by another ` +
          `tenant who would inherit the name. This is a low-confidence stale-DNS heuristic, not ` +
          `proven takeover.`,
        evidence: {
          confidence: "heuristic",
          severityRationale: {
            base: "low",
            modifiers: [],
            final: "low",
            formula: "record → account's own unassigned reserved IP ⇒ stale-DNS heuristic, low",
          },
          danglingRecords: dangling.map((r) => ({
            name: r.name ?? null,
            type: r.type ?? null,
            target: r.data ?? null,
          })),
          note:
            "External IPs are not flagged; only records pointing at the account's own " +
            "unassigned reserved IPs, which is the API-detectable stale-DNS case.",
        },
        remediation:
          "Point the record at a live resource, or remove it. If the reserved IP is unused, " +
          "release it and delete the record so the name does not dangle.",
        stableElement: dangling
          .map((r) => `${r.name ?? "@"}:${r.type}:${r.data}`)
          .sort()
          .join("|"),
        coverageKeys: ["reserved_ips", "domains", `dns_records:${domainName}`],
      });
    }

    return findings;
  },
};
