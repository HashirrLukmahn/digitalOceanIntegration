/**
 * DigitalOcean API response shapes.
 *
 * Every field here was read from DigitalOcean's public OpenAPI specification
 * (github.com/digitalocean/openapi) rather than recalled, because the exposure rules
 * depend on exact field names and a wrong guess produces a confidently wrong finding.
 *
 * These are intentionally partial: only the fields this app reads are modelled.
 */

/** Every paginated list response carries this envelope. */
export interface DoPaginated {
  links?: {
    pages?: {
      first?: string;
      prev?: string;
      next?: string;
      last?: string;
    };
  };
  meta?: { total?: number };
}

export interface DoAccountResponse {
  account?: {
    uuid?: string;
    email?: string;
    status?: string;
    team?: { uuid?: string; name?: string };
  };
}

export interface DoRegion {
  slug?: string;
  name?: string;
}

export interface DoProject {
  id: string;
  name: string;
  description?: string;
  purpose?: string;
  environment?: string;
  is_default?: boolean;
  owner_uuid?: string;
  created_at?: string;
  updated_at?: string;
}

/**
 * Project membership is reported as a URN, e.g. `do:droplet:123`. This happens to be
 * the same format the specification requires for `externalId`, so membership maps
 * directly onto collected resources with no translation table.
 */
export interface DoProjectResource {
  urn: string;
  assigned_at?: string;
  status?: string;
}

export interface DoNetworkV4 {
  ip_address?: string;
  netmask?: string;
  gateway?: string;
  /** "public" or "private". The only reliable signal that a droplet has a public IP. */
  type?: string;
}

export interface DoNetworkV6 {
  ip_address?: string;
  netmask?: number;
  gateway?: string;
  type?: string;
}

export interface DoDroplet {
  id: number;
  name: string;
  status?: string;
  created_at?: string;
  region?: DoRegion;
  size_slug?: string;
  networks?: { v4?: DoNetworkV4[]; v6?: DoNetworkV6[] };
  vpc_uuid?: string;
  tags?: string[];
  image?: { slug?: string; distribution?: string };
}

/**
 * `ports` is a STRING, and the string "0" means *all ports for this protocol* -- not
 * port zero. Misreading it turns "everything is open" into "port 0 is open".
 */
export interface DoFirewallRuleTarget {
  addresses?: string[];
  droplet_ids?: number[];
  load_balancer_uids?: string[];
  kubernetes_ids?: string[];
  tags?: string[];
}

export interface DoFirewallInboundRule {
  protocol: string;
  ports: string;
  sources?: DoFirewallRuleTarget;
}

export interface DoFirewallOutboundRule {
  protocol: string;
  ports: string;
  destinations?: DoFirewallRuleTarget;
}

export interface DoFirewall {
  id: string;
  name: string;
  status?: string;
  created_at?: string;
  inbound_rules?: DoFirewallInboundRule[];
  outbound_rules?: DoFirewallOutboundRule[];
  droplet_ids?: number[];
  tags?: string[];
}

export interface DoForwardingRule {
  entry_protocol?: string;
  entry_port?: number;
  target_protocol?: string;
  target_port?: number;
  tls_passthrough?: boolean;
}

export interface DoLoadBalancer {
  id: string;
  name: string;
  /** Public-facing IP. Empty string while the load balancer is still provisioning. */
  ip?: string;
  /**
   * "EXTERNAL" or "INTERNAL" -- provider-reported, and a far better signal than
   * inferring public-ness from the presence of an IP address.
   */
  network?: string;
  region?: DoRegion;
  status?: string;
  created_at?: string;
  forwarding_rules?: DoForwardingRule[];
  droplet_ids?: number[];
  tag?: string;
  vpc_uuid?: string;
  redirect_http_to_https?: boolean;
}

export interface DoVpc {
  id: string;
  name: string;
  region?: string;
  ip_range?: string;
  default?: boolean;
  created_at?: string;
  description?: string;
}

export interface DoDatabaseConnection {
  host?: string;
  port?: number;
  ssl?: boolean;
  database?: string;
  /** Contains credentials. Never copied into metadata or logs. */
  uri?: string;
  user?: string;
  password?: string;
}

export interface DoDatabaseCluster {
  id: string;
  name: string;
  engine?: string;
  version?: string;
  status?: string;
  region?: string;
  num_nodes?: number;
  created_at?: string;
  tags?: string[];
  private_network_uuid?: string;
  connection?: DoDatabaseConnection;
  private_connection?: DoDatabaseConnection;
}

/**
 * Trusted sources. Note the absence of a "vpc" type: trust is expressed per droplet,
 * per k8s cluster, per tag, per app, or per IP -- so any claim that a database
 * "trusts the whole VPC" would be unsupported by the API.
 */
export interface DoDatabaseFirewallRule {
  uuid?: string;
  cluster_uuid?: string;
  type: "droplet" | "k8s" | "ip_addr" | "tag" | "app" | string;
  value: string;
  created_at?: string;
}

/**
 * Control-plane firewall is nullable and, at time of writing, invite-only early
 * availability. `null` means "we cannot tell", NOT "unrestricted" -- treating it as
 * unrestricted would raise a finding on essentially every real cluster.
 */
export interface DoControlPlaneFirewall {
  enabled?: boolean;
  allowed_addresses?: string[];
}

export interface DoKubernetesCluster {
  id: string;
  name: string;
  region?: string;
  version?: string;
  /** Public control-plane endpoint URL. */
  endpoint?: string;
  ipv4?: string;
  vpc_uuid?: string;
  tags?: string[];
  created_at?: string;
  status?: { state?: string; message?: string };
  control_plane_firewall?: DoControlPlaneFirewall | null;
  node_pools?: Array<{ id?: string; name?: string; count?: number; size?: string }>;
}

export interface DoAppSpecDatabase {
  name?: string;
  engine?: string;
  cluster_name?: string;
  production?: boolean;
}

/**
 * An App Platform environment variable.
 *
 * `type` defaults to GENERAL, and GENERAL values are returned in PLAINTEXT by the
 * ordinary `/v2/apps` listing. Only SECRET values are encrypted. This is the quiet
 * hazard of collecting apps: third-party credentials arrive without calling anything
 * that looks dangerous, which is why the metadata allowlist never copies `spec`.
 */
export interface DoAppEnvVar {
  key?: string;
  scope?: string;
  type?: "GENERAL" | "SECRET" | string;
  value?: string;
}

export interface DoAppComponent {
  name?: string;
  envs?: DoAppEnvVar[];
}

export interface DoApp {
  id: string;
  spec?: {
    name?: string;
    region?: string;
    databases?: DoAppSpecDatabase[];
    /** App-level variables, shared by every component. */
    envs?: DoAppEnvVar[];
    services?: DoAppComponent[];
    workers?: DoAppComponent[];
    jobs?: DoAppComponent[];
    functions?: DoAppComponent[];
    static_sites?: DoAppComponent[];
  };
  /** Public ingress hostname assigned by App Platform. */
  default_ingress?: string;
  live_url?: string;
  live_domain?: string;
  region?: DoRegion;
  created_at?: string;
  updated_at?: string;
  active_deployment?: { id?: string; phase?: string };
}

export interface DoVolume {
  id: string;
  name: string;
  region?: DoRegion;
  droplet_ids?: number[];
  size_gigabytes?: number;
  filesystem_type?: string;
  tags?: string[];
  created_at?: string;
}

export interface DoRegistry {
  name: string;
  region?: string;
  created_at?: string;
  storage_usage_bytes?: number;
}
