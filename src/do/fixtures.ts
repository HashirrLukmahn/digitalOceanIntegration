import type { DoHttp, QueryParams } from "./http";
import type { Fetcher, SpacesConfig } from "./spaces";

/**
 * Fixture transport.
 *
 * `DATA_SOURCE=fixtures` swaps only this layer, so collectors, pagination,
 * normalization and every exposure rule run exactly the code path they run against
 * the live API. That is the point: a fixture mode that bypassed the collectors would
 * demonstrate the UI while proving nothing about the logic underneath it.
 *
 * The dataset is built to exercise each rule *and* each rule's negative case, so an
 * evaluator with no DigitalOcean account can see both that findings appear and that
 * they do not appear where they should not.
 *
 * Droplets are served across two pages so fixture mode also exercises pagination.
 */

const TEAM = { uuid: "team-1f4d2c9a", name: "Acme Platform" };

const DROPLET_PAGE_1 = [
  {
    // Firewalled, but the firewall admits the world on SSH -> high severity finding.
    id: 101,
    name: "web-01",
    status: "active",
    created_at: "2025-03-04T10:12:00Z",
    region: { slug: "nyc3", name: "New York 3" },
    size_slug: "s-2vcpu-4gb",
    vpc_uuid: "vpc-prod-1",
    tags: ["web", "env:production"],
    networks: {
      v4: [
        { ip_address: "203.0.113.24", netmask: "255.255.240.0", gateway: "203.0.113.1", type: "public" },
        { ip_address: "10.108.0.4", netmask: "255.255.240.0", type: "private" },
      ],
      v6: [],
    },
  },
  {
    // No firewall at all, and publicly addressable -> "no firewall" finding.
    id: 102,
    name: "legacy-reporting",
    status: "active",
    created_at: "2024-08-19T08:40:00Z",
    region: { slug: "nyc3", name: "New York 3" },
    size_slug: "s-1vcpu-2gb",
    vpc_uuid: "vpc-prod-1",
    tags: ["legacy"],
    networks: {
      v4: [
        { ip_address: "203.0.113.77", netmask: "255.255.240.0", gateway: "203.0.113.1", type: "public" },
      ],
      v6: [],
    },
  },
];

const DROPLET_PAGE_2 = [
  {
    // Private only. Must produce no findings however permissive anything else is.
    id: 103,
    name: "internal-worker",
    status: "active",
    created_at: "2025-01-22T14:02:00Z",
    region: { slug: "nyc3", name: "New York 3" },
    size_slug: "s-2vcpu-4gb",
    vpc_uuid: "vpc-prod-1",
    tags: ["worker", "env:production"],
    networks: { v4: [{ ip_address: "10.108.0.9", netmask: "255.255.240.0", type: "private" }], v6: [] },
  },
  {
    // Public, and protected by a tag-attached firewall scoped to a bastion range.
    // Exercises the tag-attachment path that would otherwise cause a false positive.
    id: 104,
    name: "api-02",
    status: "active",
    created_at: "2025-05-30T09:15:00Z",
    region: { slug: "ams3", name: "Amsterdam 3" },
    size_slug: "s-2vcpu-2gb",
    vpc_uuid: "vpc-prod-1",
    tags: ["api"],
    networks: {
      v4: [
        { ip_address: "198.51.100.12", netmask: "255.255.240.0", gateway: "198.51.100.1", type: "public" },
        { ip_address: "10.108.0.12", netmask: "255.255.240.0", type: "private" },
      ],
      v6: [],
    },
  },
];

const FIXTURES: Record<string, unknown> = {
  "/v2/account": {
    account: {
      uuid: "acct-9c2e",
      email: "platform@acme.example",
      status: "active",
      team: TEAM,
    },
  },

  "/v2/projects": {
    projects: [
      {
        id: "proj-prod",
        name: "Production",
        description: "Customer-facing production workloads",
        purpose: "Web Application",
        environment: "Production",
        is_default: true,
        created_at: "2024-06-01T00:00:00Z",
      },
    ],
    links: { pages: {} },
  },

  "/v2/projects/proj-prod/resources": {
    resources: [
      { urn: "do:droplet:101", assigned_at: "2025-03-04T10:12:00Z", status: "ok" },
      { urn: "do:droplet:102", assigned_at: "2024-08-19T08:40:00Z", status: "ok" },
      { urn: "do:droplet:103", assigned_at: "2025-01-22T14:02:00Z", status: "ok" },
      { urn: "do:droplet:104", assigned_at: "2025-05-30T09:15:00Z", status: "ok" },
      { urn: "do:dbaas:db-orders", assigned_at: "2024-09-01T00:00:00Z", status: "ok" },
      { urn: "do:dbaas:db-analytics", assigned_at: "2024-11-11T00:00:00Z", status: "ok" },
      { urn: "do:loadbalancer:lb-public", assigned_at: "2025-02-01T00:00:00Z", status: "ok" },
      { urn: "do:kubernetes:k8s-prod", assigned_at: "2025-04-01T00:00:00Z", status: "ok" },
      { urn: "do:app:app-storefront", assigned_at: "2025-06-01T00:00:00Z", status: "ok" },
      { urn: "do:space:acme-public-assets", assigned_at: "2024-07-15T00:00:00Z", status: "ok" },
      { urn: "do:space:acme-backups", assigned_at: "2024-07-15T00:00:00Z", status: "ok" },
      // Deliberately references a type this app does not inventory; must be dropped
      // rather than left as a dangling edge.
      { urn: "do:image:9999", assigned_at: "2025-06-01T00:00:00Z", status: "ok" },
    ],
    links: { pages: {} },
  },

  // Two pages, so fixture mode exercises the pagination follower.
  "/v2/droplets": {
    droplets: DROPLET_PAGE_1,
    links: { pages: { next: "https://api.digitalocean.com/v2/droplets?page=2&per_page=200" } },
    meta: { total: 4 },
  },
  "https://api.digitalocean.com/v2/droplets?page=2&per_page=200": {
    droplets: DROPLET_PAGE_2,
    links: { pages: { first: "https://api.digitalocean.com/v2/droplets?page=1&per_page=200" } },
    meta: { total: 4 },
  },

  "/v2/firewalls": {
    firewalls: [
      {
        id: "fw-web",
        name: "web-public",
        status: "succeeded",
        created_at: "2025-03-04T10:00:00Z",
        droplet_ids: [101],
        tags: [],
        inbound_rules: [
          { protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0", "::/0"] } },
          { protocol: "tcp", ports: "80", sources: { addresses: ["0.0.0.0/0", "::/0"] } },
          // The problem: administrative access open to the entire internet.
          { protocol: "tcp", ports: "22", sources: { addresses: ["0.0.0.0/0"] } },
        ],
        outbound_rules: [
          { protocol: "tcp", ports: "0", destinations: { addresses: ["0.0.0.0/0", "::/0"] } },
        ],
      },
      {
        id: "fw-api",
        name: "api-bastion-only",
        status: "succeeded",
        created_at: "2025-05-30T09:00:00Z",
        droplet_ids: [],
        // Attached by tag, not by id -- the case that produces false positives if
        // tag attachment is not resolved.
        tags: ["api"],
        inbound_rules: [
          { protocol: "tcp", ports: "443", sources: { addresses: ["0.0.0.0/0"] } },
          { protocol: "tcp", ports: "22", sources: { addresses: ["198.51.100.0/24"] } },
        ],
        outbound_rules: [],
      },
    ],
    links: { pages: {} },
  },

  "/v2/load_balancers": {
    load_balancers: [
      {
        id: "lb-public",
        name: "prod-edge",
        ip: "203.0.113.200",
        network: "EXTERNAL",
        status: "active",
        created_at: "2025-02-01T00:00:00Z",
        region: { slug: "nyc3", name: "New York 3" },
        vpc_uuid: "vpc-prod-1",
        redirect_http_to_https: true,
        droplet_ids: [101, 104],
        forwarding_rules: [
          {
            entry_protocol: "https",
            entry_port: 443,
            target_protocol: "http",
            target_port: 80,
            // Binds the expired edge certificate to a public listener -> escalated finding.
            certificate_id: "cert-edge",
          },
          { entry_protocol: "http", entry_port: 80, target_protocol: "http", target_port: 80 },
        ],
      },
      {
        // Internal: must produce no finding despite having an address.
        id: "lb-internal",
        name: "internal-mesh",
        ip: "10.108.0.200",
        network: "INTERNAL",
        status: "active",
        created_at: "2025-02-01T00:00:00Z",
        region: { slug: "nyc3", name: "New York 3" },
        vpc_uuid: "vpc-prod-1",
        droplet_ids: [103],
        forwarding_rules: [
          { entry_protocol: "http", entry_port: 8080, target_protocol: "http", target_port: 8080 },
        ],
      },
    ],
    links: { pages: {} },
  },

  "/v2/certificates": {
    certificates: [
      {
        // Custom certificate, already expired, and bound to the public edge load balancer
        // -> escalated to high. Uses a fixed past date so it is expired at any run time.
        id: "cert-edge",
        name: "prod-edge-cert",
        type: "custom",
        state: "verified",
        not_after: "2025-01-01T00:00:00Z",
        sha1_fingerprint: "aa:bb:cc",
        dns_names: ["shop.acme.example"],
        created_at: "2023-01-01T00:00:00Z",
      },
      {
        // Healthy Let's Encrypt certificate far from expiry -> auto-renews, no finding.
        id: "cert-le",
        name: "api-le-cert",
        type: "lets_encrypt",
        state: "verified",
        not_after: "2030-01-01T00:00:00Z",
        sha1_fingerprint: "dd:ee:ff",
        dns_names: ["api.acme.example"],
        created_at: "2025-06-01T00:00:00Z",
      },
    ],
    links: { pages: {} },
  },

  "/v2/reserved_ips": {
    reserved_ips: [
      // Assigned to web-01 -> no finding.
      { ip: "203.0.113.240", region: { slug: "nyc3" }, droplet: { id: 101, name: "web-01" } },
      // Held but attached to nothing -> informational finding, and the target of a stale record.
      { ip: "203.0.113.250", region: { slug: "nyc3" }, droplet: null },
    ],
    links: { pages: {} },
  },

  "/v2/domains": {
    domains: [{ name: "acme.example", ttl: 1800 }],
    links: { pages: {} },
  },
  "/v2/domains/acme.example/records": {
    domain_records: [
      // Points at the account's own UNASSIGNED reserved IP -> stale-DNS heuristic.
      { id: 1, type: "A", name: "stale", data: "203.0.113.250", ttl: 300 },
      // Points at the live public load balancer IP -> a live target, must NOT be flagged.
      { id: 2, type: "A", name: "@", data: "203.0.113.200", ttl: 300 },
      // Not an address record -> ignored.
      { id: 3, type: "CNAME", name: "www", data: "acme.example.", ttl: 300 },
    ],
    links: { pages: {} },
  },

  "/v2/vpcs": {
    vpcs: [
      {
        id: "vpc-prod-1",
        name: "prod-nyc3",
        region: "nyc3",
        ip_range: "10.108.0.0/20",
        default: true,
        description: "Default production VPC",
        created_at: "2024-06-01T00:00:00Z",
      },
    ],
    links: { pages: {} },
  },

  "/v2/databases": {
    databases: [
      {
        id: "db-orders",
        name: "orders-pg",
        engine: "pg",
        version: "15",
        status: "online",
        region: "nyc3",
        num_nodes: 2,
        created_at: "2024-09-01T00:00:00Z",
        tags: ["env:production"],
        private_network_uuid: "vpc-prod-1",
        connection: {
          host: "orders-pg-do-user-1.b.db.ondigitalocean.com",
          port: 25060,
          ssl: true,
          database: "defaultdb",
          user: "doadmin",
          // Present in the real API payload, and must never reach metadata or logs.
          password: "REDACT-ME-fixture-password",
          uri: "postgresql://doadmin:REDACT-ME-fixture-password@orders-pg-do-user-1.b.db.ondigitalocean.com:25060/defaultdb?sslmode=require",
        },
        private_connection: {
          host: "private-orders-pg-do-user-1.b.db.ondigitalocean.com",
          port: 25060,
        },
      },
      {
        id: "db-analytics",
        name: "analytics-mysql",
        engine: "mysql",
        version: "8",
        status: "online",
        region: "nyc3",
        num_nodes: 1,
        created_at: "2024-11-11T00:00:00Z",
        tags: [],
        connection: {
          host: "analytics-mysql-do-user-1.b.db.ondigitalocean.com",
          port: 25060,
          ssl: true,
          user: "doadmin",
          password: "REDACT-ME-fixture-password-2",
          uri: "mysql://doadmin:REDACT-ME-fixture-password-2@analytics-mysql-do-user-1.b.db.ondigitalocean.com:25060/defaultdb",
        },
      },
    ],
    links: { pages: {} },
  },

  // Properly restricted: trusted sources naming specific droplets.
  "/v2/databases/db-orders/firewall": {
    rules: [
      { uuid: "r1", cluster_uuid: "db-orders", type: "droplet", value: "101", created_at: "2024-09-01T00:00:00Z" },
      { uuid: "r2", cluster_uuid: "db-orders", type: "droplet", value: "104", created_at: "2024-09-01T00:00:00Z" },
    ],
  },
  // Trusted-source list exists but allows the entire internet.
  "/v2/databases/db-analytics/firewall": {
    rules: [
      { uuid: "r3", cluster_uuid: "db-analytics", type: "ip_addr", value: "0.0.0.0/0", created_at: "2024-11-11T00:00:00Z" },
    ],
  },

  "/v2/kubernetes/clusters": {
    kubernetes_clusters: [
      {
        id: "k8s-prod",
        name: "prod-cluster",
        region: "nyc3",
        version: "1.31.1-do.0",
        endpoint: "https://k8s-prod.k8s.ondigitalocean.com",
        ipv4: "203.0.113.150",
        vpc_uuid: "vpc-prod-1",
        tags: ["env:production"],
        created_at: "2025-04-01T00:00:00Z",
        status: { state: "running" },
        // Explicitly disabled -> a finding. Contrast with k8s-staging below.
        control_plane_firewall: { enabled: false, allowed_addresses: [] },
        node_pools: [{ id: "np-1", name: "default", count: 3, size: "s-2vcpu-4gb" }],
      },
      {
        id: "k8s-staging",
        name: "staging-cluster",
        region: "ams3",
        version: "1.31.1-do.0",
        endpoint: "https://k8s-staging.k8s.ondigitalocean.com",
        vpc_uuid: "vpc-prod-1",
        tags: [],
        created_at: "2025-04-02T00:00:00Z",
        status: { state: "running" },
        // Restricted allowlist -> no finding.
        control_plane_firewall: { enabled: true, allowed_addresses: ["198.51.100.0/24"] },
        node_pools: [{ id: "np-2", name: "default", count: 2, size: "s-2vcpu-2gb" }],
      },
      {
        id: "k8s-legacy",
        name: "legacy-cluster",
        region: "nyc1",
        version: "1.29.0-do.0",
        endpoint: "https://k8s-legacy.k8s.ondigitalocean.com",
        tags: [],
        created_at: "2024-02-02T00:00:00Z",
        status: { state: "running" },
        // null: the invite-only field is unavailable on this account. Must produce NO
        // control-plane finding -- "cannot tell" is not "unrestricted".
        control_plane_firewall: null,
        // Auto-upgrade explicitly off -> a low-severity patch-hygiene finding. This is the
        // only finding this cluster produces, and it does not mark the cluster exposed.
        auto_upgrade: false,
        node_pools: [],
      },
    ],
    links: { pages: {} },
  },

  // Per-cluster available upgrades. prod and legacy are current; staging has a patch
  // upgrade available (1.31.1 -> 1.31.3) -> a low-severity patch-currency finding.
  "/v2/kubernetes/clusters/k8s-prod/upgrades": { available_upgrade_versions: [] },
  "/v2/kubernetes/clusters/k8s-staging/upgrades": {
    available_upgrade_versions: [{ slug: "1.31.3-do.0", kubernetes_version: "1.31.3-do.0" }],
  },
  "/v2/kubernetes/clusters/k8s-legacy/upgrades": { available_upgrade_versions: [] },

  "/v2/apps": {
    apps: [
      {
        id: "app-storefront",
        spec: {
          name: "storefront",
          region: "nyc",
          databases: [
            { name: "orders", engine: "PG", cluster_name: "orders-pg", production: true },
          ],
          envs: [
            // Correctly marked: encrypted by DigitalOcean, must NOT be flagged.
            { key: "SESSION_SECRET", scope: "RUN_TIME", type: "SECRET", value: "EV[1:encrypted]" },
            // Ordinary configuration: not credential-shaped, must NOT be flagged.
            { key: "LOG_LEVEL", scope: "RUN_AND_BUILD_TIME", type: "GENERAL", value: "info" },
            { key: "SORT_KEY", scope: "RUN_TIME", type: "GENERAL", value: "created_at" },
          ],
          services: [
            {
              name: "web",
              envs: [
                // Credential-shaped and left at the GENERAL default -> flagged.
                {
                  key: "STRIPE_API_KEY",
                  scope: "RUN_TIME",
                  type: "GENERAL",
                  value: "sk_live_FIXTURE_SHOULD_NEVER_BE_STORED",
                },
                // No `type` at all: GENERAL is the default, so this is plaintext too.
                {
                  key: "DATABASE_URL",
                  scope: "RUN_TIME",
                  value: "postgresql://user:FIXTURE_PASSWORD@db.internal:5432/app",
                },
              ],
            },
          ],
        },
        default_ingress: "https://storefront-abc12.ondigitalocean.app",
        live_url: "https://storefront-abc12.ondigitalocean.app",
        live_domain: "shop.acme.example",
        region: { slug: "nyc", name: "New York" },
        created_at: "2025-06-01T00:00:00Z",
        updated_at: "2025-08-01T00:00:00Z",
        active_deployment: { id: "dep-1", phase: "ACTIVE" },
      },
    ],
    links: { pages: {} },
  },

  "/v2/volumes": {
    volumes: [
      {
        id: "vol-data-1",
        name: "orders-data",
        region: { slug: "nyc3", name: "New York 3" },
        droplet_ids: [101],
        size_gigabytes: 250,
        filesystem_type: "ext4",
        tags: ["env:production"],
        created_at: "2025-03-04T10:20:00Z",
      },
    ],
    links: { pages: {} },
  },

  "/v2/registries": {
    registries: [
      {
        name: "acme-registry",
        region: "nyc3",
        created_at: "2024-07-01T00:00:00Z",
        storage_usage_bytes: 4_182_310_912,
      },
    ],
    links: { pages: {} },
  },
};

/**
 * Spaces in sample-data mode.
 *
 * Every other collector swaps transport through `DoHttp`. Spaces cannot: detecting a
 * public bucket is an anonymous request straight to the S3-compatible endpoint, which
 * has no v2 equivalent to record. Left alone, sample-data mode would reach the real
 * internet for this one collector and report a run that is part recorded, part live.
 *
 * `acme-public-assets` answers 200 to an unauthenticated list, which is what proves
 * public access by demonstration. `acme-backups` answers 403, so the corpus carries
 * the true negative next to the finding.
 */
export const FIXTURE_SPACES: SpacesConfig = {
  buckets: [
    { region: "nyc3", name: "acme-public-assets" },
    { region: "nyc3", name: "acme-backups" },
  ],
};

export const fixtureSpacesFetcher: Fetcher = async (url) => {
  const status = url.includes("acme-public-assets") ? 200 : 403;
  return { status, text: async () => "" };
};

export class FixtureDoHttp implements DoHttp {
  readonly calls: string[] = [];

  async get<T>(pathOrUrl: string, _query?: QueryParams): Promise<T> {
    this.calls.push(pathOrUrl);
    if (pathOrUrl in FIXTURES) return FIXTURES[pathOrUrl] as T;

    // Unknown paths behave like an empty collection rather than throwing, so adding a
    // collector does not require inventing a fixture before the app will boot.
    return { links: { pages: {} } } as T;
  }
}
