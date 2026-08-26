import type { DoFirewall, DoFirewallInboundRule } from "../do/types";
import { isPublicInternetCidr, parsePorts } from "./ports";

/**
 * Effective firewall policy.
 *
 * DigitalOcean cloud firewalls are allow-only: an inbound rule names permitted sources for
 * a port range, and anything not permitted is denied by default. So the "effective policy"
 * for a droplet is the union of its attached firewalls' inbound allows -- there are no deny
 * rules to subtract. These helpers answer the one question the cross-resource rules need:
 * given a port, does the set of firewalls attached to a droplet actually admit traffic to
 * it, and from where?
 *
 * Keeping this in one place is what lets a rule reason about a *path* (public entry ->
 * forwarding rule -> backend port) rather than a single field, which is the difference
 * between "this port is listed somewhere" and "an attacker can actually reach it".
 */

/** Whether an inbound rule's protocol and port range cover a specific TCP port. */
export function inboundRuleCoversPort(rule: DoFirewallInboundRule, port: number): boolean {
  // Sensitive services here are TCP; a UDP rule on the same number is a different service.
  if (rule.protocol && rule.protocol.toLowerCase() !== "tcp") return false;
  const range = parsePorts(rule.ports);
  return range.all || (port >= range.from && port <= range.to);
}

/**
 * How, if at all, a droplet's firewalls admit traffic to `port` on behalf of a load
 * balancer.
 *
 *   "public"        a covering rule admits 0.0.0.0/0 or ::/0 -- the port is open to the
 *                   world directly, so the load balancer is not even needed to reach it.
 *   "load_balancer" a covering rule names this load balancer's uid as a source -- the
 *                   droplet trusts the LB specifically, which is the quiet "collectively
 *                   permit" case: neither the LB nor the backend looks wrong alone.
 *   null            no covering inbound rule, so the backend blocks the port and the path
 *                   does not complete however the LB is configured.
 *
 * `public` wins over `load_balancer` when both appear, because it is the broader exposure.
 */
export type BackendReachability = "public" | "load_balancer" | null;

export function backendPortReachability(
  firewalls: readonly DoFirewall[],
  port: number,
  loadBalancerId: string,
): BackendReachability {
  let viaLoadBalancer = false;

  for (const firewall of firewalls) {
    for (const rule of firewall.inbound_rules ?? []) {
      if (!inboundRuleCoversPort(rule, port)) continue;
      const sources = rule.sources;
      if (!sources) continue;
      if ((sources.addresses ?? []).some(isPublicInternetCidr)) return "public";
      if ((sources.load_balancer_uids ?? []).includes(loadBalancerId)) viaLoadBalancer = true;
    }
  }

  return viaLoadBalancer ? "load_balancer" : null;
}
