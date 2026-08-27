import type { DoFirewall, DoFirewallInboundRule } from "../do/types";
import { isPublicInternetCidr, parsePorts } from "./ports";

/**
 * Effective firewall policy.
 *
 * DigitalOcean cloud firewalls are **allow-minus-deny**: an inbound rule permits or denies
 * a port range for its sources, and -- critically -- a deny rule takes precedence across
 * *every* firewall applied to a Droplet, blocking traffic that a broad allow in another
 * firewall would otherwise permit. A rule with no `action` is an allow (the field predates
 * deny support). Anything neither allowed nor denied is denied by default.
 *
 * These helpers answer the one question the reachability rules need: given a port, does the
 * combined policy actually admit traffic to it -- from the public internet, or from a
 * specific load balancer -- once deny precedence is applied. That is the difference between
 * "a port is listed in an allow rule" and "an attacker can actually reach it".
 */

/**
 * Whether an inbound rule's protocol and port range cover a specific TCP port.
 *
 * A `protocol:"all"` rule (the shape deny-all rules take) covers every port. Otherwise the
 * protocol must be *explicitly* tcp -- a missing protocol is unknown, not "assume tcp", so a
 * partial response cannot read a UDP/ICMP allow as an open service.
 */
export function inboundRuleCoversPort(rule: DoFirewallInboundRule, port: number): boolean {
  const protocol = (rule.protocol ?? "").toLowerCase();
  if (protocol === "all") return true;
  if (protocol !== "tcp") return false;
  const range = parsePorts(rule.ports);
  return range.all || (port >= range.from && port <= range.to);
}

function isDeny(rule: DoFirewallInboundRule): boolean {
  // Absent action means allow.
  return (rule.action ?? "allow") === "deny";
}

function sourceIsPublic(rule: DoFirewallInboundRule): boolean {
  return (rule.sources?.addresses ?? []).some(isPublicInternetCidr);
}

/**
 * Whether the effective policy admits `port` from the public internet.
 *
 * Allow-minus-deny: at least one public allow covering the port, and no public deny (or
 * deny-all) covering it. Used by the droplet ingress rule to decide what is *effectively*
 * open rather than what merely appears in an allow rule.
 */
export function publicPortReachable(firewalls: readonly DoFirewall[], port: number): boolean {
  let allow = false;
  let deny = false;
  for (const firewall of firewalls) {
    for (const rule of firewall.inbound_rules ?? []) {
      if (!inboundRuleCoversPort(rule, port) || !sourceIsPublic(rule)) continue;
      if (isDeny(rule)) deny = true;
      else allow = true;
    }
  }
  return allow && !deny;
}

/**
 * Whether a public deny rule covers `port` -- so the port is blocked from the internet even
 * if some allow rule lists it. A deny-all (`protocol:"all"` or `ports:"0"`) covers everything.
 */
export function publicDenyCoversPort(firewalls: readonly DoFirewall[], port: number): boolean {
  for (const firewall of firewalls) {
    for (const rule of firewall.inbound_rules ?? []) {
      if (isDeny(rule) && sourceIsPublic(rule) && inboundRuleCoversPort(rule, port)) return true;
    }
  }
  return false;
}

/**
 * Whether a public deny fully covers a port *range* -- e.g. a deny-all, or a deny whose
 * range contains the whole allow range. Used to suppress an entire public allow rule whose
 * ports are all denied.
 */
export function publicDenyCoversRange(
  firewalls: readonly DoFirewall[],
  from: number,
  to: number,
): boolean {
  for (const firewall of firewalls) {
    for (const rule of firewall.inbound_rules ?? []) {
      if (!isDeny(rule) || !sourceIsPublic(rule)) continue;
      if ((rule.protocol ?? "").toLowerCase() === "all") return true;
      const range = parsePorts(rule.ports);
      if (range.all || (range.from <= from && range.to >= to)) return true;
    }
  }
  return false;
}

/**
 * How, if at all, a droplet's firewalls admit traffic to `port` on behalf of a load
 * balancer, after deny precedence.
 *
 *   "public"        an allow admits 0.0.0.0/0 for the port and no public deny blocks it --
 *                   the port is open to the world directly.
 *   "load_balancer" an allow names this load balancer's uid and nothing denies that path --
 *                   the quiet "collectively permit" case.
 *   null            no surviving allow, so the backend blocks the port however the LB is set.
 *
 * A public deny (or deny-all) blocks the load-balancer path too, since it denies the port
 * for all sources including the LB's traffic. `public` wins over `load_balancer` when both
 * survive, because it is the broader exposure.
 */
export type BackendReachability = "public" | "load_balancer" | null;

export function backendPortReachability(
  firewalls: readonly DoFirewall[],
  port: number,
  loadBalancerId: string,
): BackendReachability {
  let publicAllow = false;
  let publicDeny = false;
  let lbAllow = false;
  let lbDeny = false;

  for (const firewall of firewalls) {
    for (const rule of firewall.inbound_rules ?? []) {
      if (!inboundRuleCoversPort(rule, port)) continue;
      const sources = rule.sources;
      if (!sources) continue;
      const matchesPublic = (sources.addresses ?? []).some(isPublicInternetCidr);
      const matchesLb = (sources.load_balancer_uids ?? []).includes(loadBalancerId);
      if (!matchesPublic && !matchesLb) continue;

      if (isDeny(rule)) {
        if (matchesPublic) {
          publicDeny = true;
          // A public deny blocks all sources on this port, including the LB's traffic.
          lbDeny = true;
        }
        if (matchesLb) lbDeny = true;
      } else {
        if (matchesPublic) publicAllow = true;
        if (matchesLb) lbAllow = true;
      }
    }
  }

  if (publicAllow && !publicDeny) return "public";
  if (lbAllow && !lbDeny) return "load_balancer";
  return null;
}
