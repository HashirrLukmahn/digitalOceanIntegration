import { externalId } from "../../normalize/resource";
import { backendPortReachability } from "../effective-policy";
import { isPublicInternetCidr, isWebPort, SENSITIVE_PORTS } from "../ports";
import { deriveSeverity, severityEvidence, type Reachability } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * Load balancer, Kubernetes control plane, and App Platform exposure.
 *
 * These three share a theme worth stating: being public is frequently the entire
 * purpose of the resource. The specification is explicit that a public web service on
 * 443 may be intentional and should be recorded without being called critical. So
 * these rules record the exposure with full evidence and let the severity matrix keep
 * them proportionate -- a public app is `low`, not an incident.
 */

/**
 * A load balancer with a public frontend.
 *
 * `network` is provider-reported as EXTERNAL or INTERNAL, which is far more reliable
 * than inferring public-ness from the presence of an IP. Older responses may omit the
 * field, so a populated `ip` is used as the fallback signal.
 */
export const loadBalancerPublicRule: ExposureRule = {
  kind: "load_balancer.public_frontend",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const lb of inventory.loadBalancers) {
      const declaredExternal = lb.network?.toUpperCase() === "EXTERNAL";
      const declaredInternal = lb.network?.toUpperCase() === "INTERNAL";
      const hasPublicIp = Boolean(lb.ip && lb.ip.length > 0);

      if (declaredInternal) continue;
      if (!declaredExternal && !hasPublicIp) continue;

      const entryPorts = (lb.forwarding_rules ?? [])
        .map((rule) => rule.entry_port)
        .filter((port): port is number => typeof port === "number");

      const sensitive = entryPorts.filter((port) => SENSITIVE_PORTS.has(port));
      const reachability: Reachability =
        sensitive.length > 0
          ? "sensitive_ports"
          : entryPorts.length > 0 && entryPorts.every(isWebPort)
            ? "web_ports"
            : entryPorts.length === 0
              ? "restricted"
              : "web_ports";

      // network=EXTERNAL is stated by DigitalOcean (provider_reported); falling back to a
      // populated public IP is a deterministic inference (derived).
      const confidence = declaredExternal ? "provider_reported" : "derived";
      const derivation = deriveSeverity("none", reachability);

      findings.push({
        resourceExternalId: externalId("loadBalancer", lb.id),
        kind: "load_balancer.public_frontend",
        severity: derivation.final,
        confidence,
        provesInternetExposure: true,
        title:
          sensitive.length > 0
            ? "Load balancer forwards a sensitive port from the internet"
            : "Load balancer has a public frontend",
        summary:
          `Load balancer "${lb.name}" is internet-facing` +
          (lb.ip ? ` at ${lb.ip}` : "") +
          (entryPorts.length > 0 ? `, accepting traffic on port(s) ${entryPorts.join(", ")}` : "") +
          `. It forwards to ${(lb.droplet_ids ?? []).length} droplet backend(s).` +
          (sensitive.length > 0
            ? ` Port(s) ${sensitive.join(", ")} map to services that are not normally exposed.`
            : " A public frontend is expected for a public service; this is recorded for inventory completeness."),
        evidence: {
          ...severityEvidence(confidence, derivation),
          network: lb.network ?? null,
          publicAddress: lb.ip || null,
          entryPorts,
          sensitiveEntryPorts: sensitive,
          forwardingRules: (lb.forwarding_rules ?? []).map((rule) => ({
            entryProtocol: rule.entry_protocol ?? null,
            entryPort: rule.entry_port ?? null,
            targetProtocol: rule.target_protocol ?? null,
            targetPort: rule.target_port ?? null,
          })),
          backendDropletIds: lb.droplet_ids ?? [],
          redirectHttpToHttps: lb.redirect_http_to_https ?? false,
          determinedBy: declaredExternal ? "network=EXTERNAL" : "public ip present",
        },
        remediation:
          sensitive.length > 0
            ? "Remove the sensitive forwarding rule, or place the service behind an authenticated " +
              "proxy. If the port is required, restrict access with a cloud firewall on the backends."
            : "No action required if this service is meant to be public. Confirm TLS is terminated " +
              "and that HTTP traffic is redirected to HTTPS.",
        stableElement: `public-frontend:${entryPorts.slice().sort((a, b) => a - b).join(",")}`,
      });
    }

    return findings;
  },
};

/**
 * A Kubernetes control plane reachable from the internet.
 *
 * `control_plane_firewall` is nullable and, at time of writing, an invite-only early
 * availability feature. `null` therefore means "this account cannot tell us", NOT
 * "unrestricted" -- and since most accounts return null, treating null as unrestricted
 * would raise a finding on essentially every cluster in existence. The rule fires only
 * when DigitalOcean actually tells us the control plane is unrestricted.
 *
 * Severity is deliberately moderate: the endpoint is authenticated, so an open control
 * plane is meaningful attack surface rather than an open door.
 */
export const kubernetesPublicEndpointRule: ExposureRule = {
  kind: "kubernetes.public_control_plane",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const cluster of inventory.kubernetes) {
      if (!cluster.endpoint) continue;

      const firewall = cluster.control_plane_firewall;
      if (firewall === null || firewall === undefined) continue; // unknown, not open

      const enabled = firewall.enabled === true;
      const allowed = firewall.allowed_addresses ?? [];
      const publicEntry = allowed.find(isPublicInternetCidr) ?? null;

      // Restricted: firewall on, and nothing in the allowlist admits the whole internet.
      if (enabled && !publicEntry) continue;

      const derivation = deriveSeverity("credential", "web_ports");

      findings.push({
        resourceExternalId: externalId("kubernetes", cluster.id),
        kind: "kubernetes.public_control_plane",
        severity: derivation.final,
        confidence: "provider_reported",
        provesInternetExposure: true,
        title: "Kubernetes control plane is reachable from any address",
        summary:
          `Cluster "${cluster.name}" exposes its API server at ${cluster.endpoint}` +
          (enabled
            ? ` and its control-plane firewall allows ${publicEntry}, which admits every address.`
            : " and its control-plane firewall is disabled, so no source restriction applies."),
        evidence: {
          ...severityEvidence("provider_reported", derivation),
          endpoint: cluster.endpoint,
          controlPlaneFirewallEnabled: firewall.enabled ?? false,
          allowedAddresses: allowed,
          publicAllowlistEntry: publicEntry,
          version: cluster.version ?? null,
          // Named so a reader knows why other clusters produced no finding.
          determinedBy: enabled ? "allowlist admits 0.0.0.0/0" : "control_plane_firewall.enabled=false",
        },
        remediation:
          "Enable the control-plane firewall and restrict allowed addresses to your " +
          "administrative and CI ranges. Kubernetes API authentication remains the primary " +
          "control, so treat this as reducing attack surface rather than closing a breach.",
        stableElement: enabled ? `allowlist:${publicEntry}` : "control-plane-firewall-disabled",
      });
    }

    return findings;
  },
};

/**
 * An App Platform app with a public ingress URL.
 *
 * Recorded because the inventory should know every internet-facing entry point, but
 * scored `low`: a public URL is what App Platform is for.
 */
export const appPublicIngressRule: ExposureRule = {
  kind: "app.public_ingress",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const app of inventory.apps) {
      const url = app.live_url ?? app.default_ingress;
      if (!url) continue;

      const name = app.spec?.name ?? app.id;

      const derivation = deriveSeverity("none", "web_ports");

      findings.push({
        resourceExternalId: externalId("app", app.id),
        kind: "app.public_ingress",
        severity: derivation.final,
        confidence: "provider_reported",
        provesInternetExposure: true,
        title: "App Platform app is publicly reachable",
        summary:
          `App "${name}" serves traffic publicly at ${url}. This is the expected behaviour for ` +
          `an App Platform service and is recorded so the inventory reflects every ` +
          `internet-facing entry point.`,
        evidence: {
          ...severityEvidence("provider_reported", derivation),
          liveUrl: app.live_url ?? null,
          defaultIngress: app.default_ingress ?? null,
          liveDomain: app.live_domain ?? null,
          deploymentPhase: app.active_deployment?.phase ?? null,
          attachedDatabases: (app.spec?.databases ?? []).map((db) => ({
            name: db.name ?? null,
            engine: db.engine ?? null,
            clusterName: db.cluster_name ?? null,
          })),
        },
        remediation:
          "No action required if the app is meant to be public. Confirm that any admin routes " +
          "are authenticated and that attached databases are not separately exposed.",
        stableElement: "public-ingress",
      });
    }

    return findings;
  },
};

/**
 * A public load balancer that forwards internet traffic to a sensitive port on a backend
 * the backend's own firewall admits.
 *
 * This is the effective-policy finding: it fires only when the frontend, the forwarding
 * rule, and the backend firewall *collectively* open the path. A public HTTPS load balancer
 * is fine; a backend firewall that trusts that load balancer on 5432 is fine; together they
 * put PostgreSQL on the internet, and neither piece looks wrong on its own. Because it
 * combines several provider facts (LB network, a forwarding rule, and one or more backend
 * firewall rules), its confidence is `derived`, never `provider_reported`.
 *
 * The path must actually complete: if no backend firewall admits the target port -- from
 * the load balancer or from the world -- the LB is forwarding into a closed door and no
 * finding is raised. That is the calibration the specification asks for over "a sensitive
 * port appears in a forwarding rule".
 */
export const loadBalancerSensitiveBackendPortRule: ExposureRule = {
  kind: "load_balancer.sensitive_backend_port",
  evaluate({ inventory, firewallsByDropletId }) {
    const findings: DraftFinding[] = [];

    for (const lb of inventory.loadBalancers) {
      const network = lb.network?.toUpperCase();
      const isPublic = network === "EXTERNAL" || (network !== "INTERNAL" && Boolean(lb.ip));
      if (!isPublic) continue;

      // Backends: explicit droplet ids plus tag-selected droplets, as the LB resolves them.
      const backendIds = new Set<number>(lb.droplet_ids ?? []);
      if (lb.tag) {
        for (const droplet of inventory.droplets) {
          if ((droplet.tags ?? []).includes(lb.tag)) backendIds.add(droplet.id);
        }
      }
      if (backendIds.size === 0) continue;

      const openPaths: Array<{
        entryPort: number | null;
        targetPort: number;
        service: string;
        reachableBackends: Array<{ dropletId: number; via: "public" | "load_balancer" }>;
      }> = [];

      for (const rule of lb.forwarding_rules ?? []) {
        const targetPort = rule.target_port;
        if (typeof targetPort !== "number") continue;
        const service = SENSITIVE_PORTS.get(targetPort);
        if (!service) continue; // only sensitive backend ports matter here

        const reachableBackends: Array<{ dropletId: number; via: "public" | "load_balancer" }> = [];
        for (const dropletId of backendIds) {
          const firewalls = firewallsByDropletId.get(dropletId) ?? [];
          const via = backendPortReachability(firewalls, targetPort, lb.id);
          if (via) reachableBackends.push({ dropletId, via });
        }

        if (reachableBackends.length > 0) {
          openPaths.push({ entryPort: rule.entry_port ?? null, targetPort, service, reachableBackends });
        }
      }

      if (openPaths.length === 0) continue;

      const services = [...new Set(openPaths.map((p) => p.service))];
      // A sensitive service reachable from the internet: none-sensitivity resource (the LB)
      // at sensitive-port reachability ⇒ high, from the same matrix the other rules use.
      const derivation = deriveSeverity("none", "sensitive_ports");

      findings.push({
        resourceExternalId: externalId("loadBalancer", lb.id),
        kind: "load_balancer.sensitive_backend_port",
        severity: derivation.final,
        // Combines the LB's public frontend, a forwarding rule, and a backend firewall rule
        // -- more than one provider fact -- so it is derived, not provider_reported.
        confidence: "derived",
        provesInternetExposure: true,
        title: `Load balancer exposes ${services.join(", ")} on a backend to the internet`,
        summary:
          `Load balancer "${lb.name}" is internet-facing and forwards to ${services.join(", ")} on ` +
          `its backend(s), and the backend firewall admits that traffic, so the path from the ` +
          `internet to the sensitive service completes. Each piece looks intentional alone; ` +
          `together they place ${services.join(", ")} on the public internet.`,
        evidence: {
          ...severityEvidence("derived", derivation),
          network: lb.network ?? null,
          publicAddress: lb.ip || null,
          paths: openPaths.map((p) => ({
            entryPort: p.entryPort,
            targetPort: p.targetPort,
            service: p.service,
            backends: p.reachableBackends.map((b) => ({
              dropletExternalId: externalId("droplet", b.dropletId),
              admittedVia: b.via === "public" ? "backend firewall allows 0.0.0.0/0" : "backend firewall trusts this load balancer",
            })),
          })),
        },
        remediation:
          "Do not forward a sensitive service through a public load balancer. Remove the " +
          "forwarding rule, or restrict the backend firewall so the port is reachable only " +
          "from the specific private sources that need it -- not from the load balancer's " +
          "public frontend.",
        stableElement: openPaths
          .map((p) => `${p.entryPort ?? "?"}->${p.targetPort}`)
          .sort()
          .join("|"),
        // Genuinely multi-collector: the LB and its forwarding rules, the backend droplets,
        // and their firewalls must all have been observed for this path to be trustworthy.
        coverageKeys: ["load_balancers", "droplets", "firewalls"],
      });
    }

    return findings;
  },
};
