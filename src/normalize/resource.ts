import type { RawInventory } from "../do/collectors";
import type { BucketProbe } from "../do/spaces";
import type {
  DoApp,
  DoCertificate,
  DoDatabaseCluster,
  DoDroplet,
  DoFirewall,
  DoKubernetesCluster,
  DoLoadBalancer,
  DoProject,
  DoRegistry,
  DoVolume,
  DoVpc,
} from "../do/types";
import { pickAllowed, withComputed } from "./metadata-allowlist";

/**
 * Raw DigitalOcean objects -> the normalized resource contract shared by the database
 * and the JSON export.
 */

export type Sensitivity = "none" | "credential" | "datastore";

export interface CloudResource {
  provider: "digitalocean";
  externalId: string;
  resourceType: string;
  name: string;
  region: string | null;
  state: string | null;
  isInternetExposed: boolean;
  sensitivity: Sensitivity;
  tags: Record<string, string>;
  metadata: Record<string, unknown>;
}

/**
 * Resource type -> URN prefix and sensitivity.
 *
 * The URN prefixes are DigitalOcean's own (`do:loadbalancer:`, `do:dbaas:`), not a
 * tidied-up version of the resource type. That is deliberate: project membership
 * arrives from the API as URNs in exactly this form, so identifiers line up without
 * a translation table.
 */
export const TYPE_TABLE = {
  project: { type: "digitalocean.project", urn: "project", sensitivity: "none" },
  droplet: { type: "digitalocean.droplet", urn: "droplet", sensitivity: "none" },
  firewall: { type: "digitalocean.firewall", urn: "firewall", sensitivity: "none" },
  loadBalancer: { type: "digitalocean.load_balancer", urn: "loadbalancer", sensitivity: "none" },
  vpc: { type: "digitalocean.vpc", urn: "vpc", sensitivity: "none" },
  kubernetes: {
    type: "digitalocean.kubernetes_cluster",
    urn: "kubernetes",
    sensitivity: "credential",
  },
  database: { type: "digitalocean.database_cluster", urn: "dbaas", sensitivity: "datastore" },
  space: { type: "digitalocean.space", urn: "space", sensitivity: "datastore" },
  app: { type: "digitalocean.app", urn: "app", sensitivity: "none" },
  registry: {
    type: "digitalocean.container_registry",
    urn: "registry",
    sensitivity: "credential",
  },
  volume: { type: "digitalocean.volume", urn: "volume", sensitivity: "datastore" },
  certificate: { type: "digitalocean.certificate", urn: "certificate", sensitivity: "none" },
} as const satisfies Record<string, { type: string; urn: string; sensitivity: Sensitivity }>;

export type TypeKey = keyof typeof TYPE_TABLE;

export function externalId(key: TypeKey, providerId: string | number): string {
  return `do:${TYPE_TABLE[key].urn}:${providerId}`;
}

/** Reverse of `externalId`: `do:dbaas:x` -> `digitalocean.database_cluster`. */
const TYPE_BY_URN: ReadonlyMap<string, string> = new Map(
  Object.values(TYPE_TABLE).map((entry) => [entry.urn, entry.type]),
);

/**
 * Resolve the normalized resource type from an external id.
 *
 * Used by reconciliation, which needs to know which resource type a finding belongs
 * to in order to decide whether this run was authoritative for it.
 */
export function resourceTypeFromExternalId(id: string): string | null {
  const parts = id.split(":");
  if (parts.length < 3 || parts[0] !== "do") return null;
  return TYPE_BY_URN.get(parts[1]!) ?? null;
}

/**
 * DigitalOcean tags are a flat array of strings; the contract calls for a map.
 *
 * The convention in the wild is `key:value`, so those are split. A bare tag becomes a
 * key with an empty value, which preserves it without inventing a value it does not
 * have. A tag containing several colons splits on the first only, since the remainder
 * is part of the value.
 */
export function normalizeTags(tags: readonly string[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const tag of tags ?? []) {
    if (!tag) continue;
    const separator = tag.indexOf(":");
    if (separator > 0) {
      out[tag.slice(0, separator)] = tag.slice(separator + 1);
    } else {
      out[tag] = "";
    }
  }
  return out;
}

function base(
  key: TypeKey,
  providerId: string | number,
  name: string,
  options: {
    region?: string | null;
    state?: string | null;
    tags?: readonly string[];
    raw: Record<string, unknown>;
    computed?: Record<string, unknown>;
  },
): CloudResource {
  const entry = TYPE_TABLE[key];
  return {
    provider: "digitalocean",
    externalId: externalId(key, providerId),
    resourceType: entry.type,
    name,
    region: options.region ?? null,
    state: options.state ?? null,
    // Set later by the exposure engine. Normalization never decides exposure.
    isInternetExposed: false,
    sensitivity: entry.sensitivity,
    tags: normalizeTags(options.tags),
    metadata: withComputed(pickAllowed(entry.type, options.raw), options.computed ?? {}),
  };
}

// --------------------------------------------------------------------------------
// Per-type normalizers
// --------------------------------------------------------------------------------

export function normalizeProject(project: DoProject): CloudResource {
  return base("project", project.id, project.name, {
    raw: project as unknown as Record<string, unknown>,
  });
}

export function normalizeDroplet(droplet: DoDroplet): CloudResource {
  const v4 = droplet.networks?.v4 ?? [];
  const publicIps = v4.filter((n) => n.type === "public").map((n) => n.ip_address).filter(Boolean);
  const privateIps = v4.filter((n) => n.type === "private").map((n) => n.ip_address).filter(Boolean);
  const publicIpv6 = (droplet.networks?.v6 ?? [])
    .filter((n) => n.type === "public")
    .map((n) => n.ip_address)
    .filter(Boolean);

  return base("droplet", droplet.id, droplet.name, {
    region: droplet.region?.slug ?? null,
    state: droplet.status ?? null,
    tags: droplet.tags,
    raw: droplet as unknown as Record<string, unknown>,
    computed: { public_ipv4: publicIps, private_ipv4: privateIps, public_ipv6: publicIpv6 },
  });
}

export function normalizeFirewall(firewall: DoFirewall): CloudResource {
  return base("firewall", firewall.id, firewall.name, {
    state: firewall.status ?? null,
    tags: firewall.tags,
    raw: firewall as unknown as Record<string, unknown>,
    computed: {
      inbound_rule_count: firewall.inbound_rules?.length ?? 0,
      outbound_rule_count: firewall.outbound_rules?.length ?? 0,
      attached_droplet_ids: firewall.droplet_ids ?? [],
    },
  });
}

export function normalizeLoadBalancer(lb: DoLoadBalancer): CloudResource {
  return base("loadBalancer", lb.id, lb.name, {
    region: lb.region?.slug ?? null,
    state: lb.status ?? null,
    raw: lb as unknown as Record<string, unknown>,
    computed: {
      public_ipv4: lb.ip || undefined,
      backend_droplet_ids: lb.droplet_ids ?? [],
      entry_ports: (lb.forwarding_rules ?? []).map((r) => r.entry_port).filter(Boolean),
    },
  });
}

export function normalizeVpc(vpc: DoVpc): CloudResource {
  return base("vpc", vpc.id, vpc.name, {
    region: vpc.region ?? null,
    raw: vpc as unknown as Record<string, unknown>,
  });
}

export function normalizeDatabase(cluster: DoDatabaseCluster): CloudResource {
  // Only the hostname and port -- never `connection.uri`, which embeds credentials.
  return base("database", cluster.id, cluster.name, {
    region: cluster.region ?? null,
    state: cluster.status ?? null,
    tags: cluster.tags,
    raw: cluster as unknown as Record<string, unknown>,
    computed: {
      public_host: cluster.connection?.host,
      public_port: cluster.connection?.port,
      private_host: cluster.private_connection?.host,
    },
  });
}

export function normalizeKubernetes(cluster: DoKubernetesCluster): CloudResource {
  return base("kubernetes", cluster.id, cluster.name, {
    region: cluster.region ?? null,
    state: cluster.status?.state ?? null,
    tags: cluster.tags,
    raw: cluster as unknown as Record<string, unknown>,
    computed: {
      endpoint: cluster.endpoint,
      node_pool_count: cluster.node_pools?.length ?? 0,
      control_plane_firewall_enabled: cluster.control_plane_firewall?.enabled ?? null,
    },
  });
}

export function normalizeApp(app: DoApp): CloudResource {
  return base("app", app.id, app.spec?.name ?? app.id, {
    region: app.region?.slug ?? app.spec?.region ?? null,
    state: app.active_deployment?.phase ?? null,
    raw: app as unknown as Record<string, unknown>,
    computed: {
      default_ingress: app.default_ingress,
      live_url: app.live_url,
      live_domain: app.live_domain,
    },
  });
}

export function normalizeVolume(volume: DoVolume): CloudResource {
  return base("volume", volume.id, volume.name, {
    region: volume.region?.slug ?? null,
    tags: volume.tags,
    raw: volume as unknown as Record<string, unknown>,
    computed: { attached_droplet_ids: volume.droplet_ids ?? [] },
  });
}

export function normalizeRegistry(registry: DoRegistry): CloudResource {
  return base("registry", registry.name, registry.name, {
    region: registry.region ?? null,
    raw: registry as unknown as Record<string, unknown>,
  });
}

/**
 * A Spaces bucket.
 *
 * Built from the probe rather than from an API object, because DigitalOcean's v2 API
 * returns no bucket object at all. Metadata carries the endpoint and the probe result
 * -- never object names or contents, which this tool has no reason to read.
 */
export function normalizeSpace(probe: BucketProbe): CloudResource {
  return base("space", probe.bucket.name, probe.bucket.name, {
    region: probe.bucket.region,
    state: probe.status === null ? "unknown" : "available",
    raw: {},
    computed: {
      endpoint: probe.endpoint,
      anonymous_probe_status: probe.status,
      publicly_listable: probe.publiclyListable,
    },
  });
}

export function normalizeCertificate(cert: DoCertificate): CloudResource {
  return base("certificate", cert.id, cert.name ?? cert.id, {
    state: cert.state ?? null,
    raw: cert as unknown as Record<string, unknown>,
    computed: {
      not_after: cert.not_after,
      cert_type: cert.type,
      dns_name_count: cert.dns_names?.length ?? 0,
    },
  });
}

/** Normalize an entire raw inventory. Order is stable for reproducible exports. */
export function normalizeInventory(inventory: RawInventory): CloudResource[] {
  return [
    ...inventory.projects.map(normalizeProject),
    ...inventory.vpcs.map(normalizeVpc),
    ...inventory.droplets.map(normalizeDroplet),
    ...inventory.firewalls.map(normalizeFirewall),
    ...inventory.loadBalancers.map(normalizeLoadBalancer),
    ...inventory.databases.map(normalizeDatabase),
    ...inventory.kubernetes.map(normalizeKubernetes),
    ...inventory.apps.map(normalizeApp),
    ...inventory.volumes.map(normalizeVolume),
    ...inventory.registries.map(normalizeRegistry),
    ...inventory.certificates.map(normalizeCertificate),
    ...inventory.spaces.map(normalizeSpace),
  ];
}
