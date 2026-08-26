import { dataSource } from "../lib/env";
import { FIXTURE_SPACES, fixtureSpacesFetcher } from "./fixtures";
import type { DoHttp } from "./http";
import { collectPaged } from "./paginate";
import {
  loadSpacesConfig,
  probeBuckets,
  spacesMode,
  verifySpacesKey,
  type BucketProbe,
  type Fetcher,
  type SpacesConfig,
  type SpacesMode,
} from "./spaces";
import type {
  DoAccountResponse,
  DoApp,
  DoCertificate,
  DoDatabaseCluster,
  DoDatabaseFirewallRule,
  DoDroplet,
  DoFirewall,
  DoKubernetesCluster,
  DoLoadBalancer,
  DoProject,
  DoProjectResource,
  DoRegistry,
  DoVolume,
  DoVpc,
} from "./types";

/**
 * Collectors.
 *
 * Each one fetches a single resource family and writes it into the raw inventory.
 * They stay raw on purpose: exposure rules need the full-fidelity provider objects
 * (a firewall rule's exact source and port range is the *evidence* for a finding),
 * while the database stores a normalized, allowlisted projection. Collapsing those
 * two into one step would force us either to store more than we should or to reason
 * about exposure with less than we have.
 *
 * A collector marked `required: false` may fail without invalidating the sync; the
 * orchestrator records it in coverage and the run ends `partial`.
 */

export interface RawInventory {
  projects: DoProject[];
  /** Project membership, as DigitalOcean URNs (already in `do:<type>:<id>` form). */
  projectResources: Array<{ projectId: string; urns: string[] }>;
  droplets: DoDroplet[];
  firewalls: DoFirewall[];
  loadBalancers: DoLoadBalancer[];
  vpcs: DoVpc[];
  databases: DoDatabaseCluster[];
  /** Trusted sources, keyed by database cluster id. */
  databaseFirewalls: Record<string, DoDatabaseFirewallRule[]>;
  kubernetes: DoKubernetesCluster[];
  apps: DoApp[];
  volumes: DoVolume[];
  registries: DoRegistry[];
  certificates: DoCertificate[];
  /** Anonymous public-read probes for configured Spaces buckets. */
  spaces: BucketProbe[];
  /** Which Spaces capability was available this run. Surfaced in coverage. */
  spacesMode: SpacesMode;
}

export function emptyInventory(): RawInventory {
  return {
    projects: [],
    projectResources: [],
    droplets: [],
    firewalls: [],
    loadBalancers: [],
    vpcs: [],
    databases: [],
    databaseFirewalls: {},
    kubernetes: [],
    apps: [],
    volumes: [],
    registries: [],
    certificates: [],
    spaces: [],
    spacesMode: "unavailable",
  };
}

/**
 * What a collector reports back after a successful run.
 *
 * `coverageKeys` are granular authoritative keys *beyond* the collector name and its
 * resource types -- the per-child keys a collector that does per-resource sub-fetches can
 * vouch for, such as `database_firewall:<clusterId>`. A collector that fetches a single
 * dataset returns nothing here; its name and resource types are key enough.
 */
export interface CollectorResult {
  coverageKeys?: string[];
}

export interface Collector {
  name: string;
  /** Required collectors are the minimum viable inventory from the specification. */
  required: boolean;
  /**
   * Normalized resource types this collector is authoritative for.
   *
   * Reconciliation is scoped by these: if the droplets collector succeeded, droplets
   * absent from the run were genuinely deleted and can be marked removed -- even
   * though some other collector failed in the same run. Without this, one flaky
   * optional collector would freeze deletion tracking for the entire inventory.
   */
  resourceTypes: readonly string[];
  run(http: DoHttp, inventory: RawInventory): Promise<CollectorResult | void>;
}

/** Raised by a collector that cannot run at all, as opposed to one that errored. */
export class CollectorUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CollectorUnavailableError";
  }
}

const pick =
  <T>(key: string) =>
  (body: unknown): T[] | undefined =>
    (body as Record<string, T[] | undefined>)?.[key];

/** Team identity for `cloud_accounts`. Not a collector -- it establishes the account. */
export async function fetchTeam(http: DoHttp): Promise<{ externalId: string; name: string }> {
  const body = await http.get<DoAccountResponse>("/v2/account");
  const team = body.account?.team;
  return {
    // Fall back to the account uuid for personal accounts with no team object.
    externalId: team?.uuid ?? body.account?.uuid ?? "unknown",
    name: team?.name ?? body.account?.email ?? "DigitalOcean account",
  };
}

// --------------------------------------------------------------------------------
// Required collectors -- the minimum viable inventory
// --------------------------------------------------------------------------------

export const projectsCollector: Collector = {
  name: "projects",
  required: true,
  resourceTypes: ["digitalocean.project"],
  async run(http, inventory) {
    inventory.projects = await collectPaged<DoProject>(http, "/v2/projects", pick("projects"));

    // Membership is a second call per project. Sequential rather than parallel: this
    // is a read-only scanner and being a polite API citizen matters more than shaving
    // a second off a sync that already takes longer than that.
    for (const project of inventory.projects) {
      const resources = await collectPaged<DoProjectResource>(
        http,
        `/v2/projects/${project.id}/resources`,
        pick("resources"),
      );
      inventory.projectResources.push({
        projectId: project.id,
        urns: resources.map((r) => r.urn).filter(Boolean),
      });
    }
  },
};

export const dropletsCollector: Collector = {
  name: "droplets",
  required: true,
  resourceTypes: ["digitalocean.droplet"],
  async run(http, inventory) {
    inventory.droplets = await collectPaged<DoDroplet>(http, "/v2/droplets", pick("droplets"));
  },
};

export const firewallsCollector: Collector = {
  name: "firewalls",
  required: true,
  resourceTypes: ["digitalocean.firewall"],
  async run(http, inventory) {
    inventory.firewalls = await collectPaged<DoFirewall>(http, "/v2/firewalls", pick("firewalls"));
  },
};

export const loadBalancersCollector: Collector = {
  name: "load_balancers",
  required: true,
  resourceTypes: ["digitalocean.load_balancer"],
  async run(http, inventory) {
    inventory.loadBalancers = await collectPaged<DoLoadBalancer>(
      http,
      "/v2/load_balancers",
      pick("load_balancers"),
    );
  },
};

export const vpcsCollector: Collector = {
  name: "vpcs",
  required: true,
  resourceTypes: ["digitalocean.vpc"],
  async run(http, inventory) {
    inventory.vpcs = await collectPaged<DoVpc>(http, "/v2/vpcs", pick("vpcs"));
  },
};

export const databasesCollector: Collector = {
  name: "databases",
  required: true,
  resourceTypes: ["digitalocean.database_cluster"],
  async run(http, inventory) {
    const databases = await collectPaged<DoDatabaseCluster>(
      http,
      "/v2/databases",
      pick("databases"),
    );
    const firewalls: Record<string, DoDatabaseFirewallRule[]> = {};

    // Trusted sources are per-cluster. Without them we cannot tell an internet-facing
    // database from one that merely has a public hostname, so publish nothing until
    // every request succeeds. A partial database snapshot could overwrite a known
    // exposure with "not exposed" simply because its firewall request failed.
    for (const cluster of databases) {
      const body = await http.get<{ rules?: DoDatabaseFirewallRule[] }>(
        `/v2/databases/${cluster.id}/firewall`,
      );
      firewalls[cluster.id] = body.rules ?? [];
    }

    inventory.databases = databases;
    inventory.databaseFirewalls = firewalls;

    // Per-child coverage: the loop above is all-or-nothing (it throws if any cluster's
    // firewall fetch fails), so on success every cluster's trusted sources are
    // authoritative. Reporting them as granular keys lets a finding or edge that depends on
    // a specific cluster's firewall reconcile on that key rather than on the whole type.
    return { coverageKeys: databases.map((cluster) => `database_firewall:${cluster.id}`) };
  },
};

// --------------------------------------------------------------------------------
// Optional collectors -- a failure here yields a partial sync, not a lost one
// --------------------------------------------------------------------------------

export const kubernetesCollector: Collector = {
  name: "kubernetes",
  required: false,
  resourceTypes: ["digitalocean.kubernetes_cluster"],
  async run(http, inventory) {
    inventory.kubernetes = await collectPaged<DoKubernetesCluster>(
      http,
      "/v2/kubernetes/clusters",
      pick("kubernetes_clusters"),
    );
  },
};

export const appsCollector: Collector = {
  name: "apps",
  required: false,
  resourceTypes: ["digitalocean.app"],
  async run(http, inventory) {
    inventory.apps = await collectPaged<DoApp>(http, "/v2/apps", pick("apps"));
  },
};

export const volumesCollector: Collector = {
  name: "volumes",
  required: false,
  resourceTypes: ["digitalocean.volume"],
  async run(http, inventory) {
    inventory.volumes = await collectPaged<DoVolume>(http, "/v2/volumes", pick("volumes"));
  },
};

export const certificatesCollector: Collector = {
  name: "certificates",
  required: false,
  resourceTypes: ["digitalocean.certificate"],
  async run(http, inventory) {
    inventory.certificates = await collectPaged<DoCertificate>(
      http,
      "/v2/certificates",
      pick("certificates"),
    );
  },
};

export const registriesCollector: Collector = {
  name: "container_registries",
  required: false,
  resourceTypes: ["digitalocean.container_registry"],
  async run(http, inventory) {
    // DigitalOcean has both a newer multi-registry endpoint and a legacy single-registry
    // one, and which works depends on the account. Try the modern shape, fall back.
    try {
      inventory.registries = await collectPaged<DoRegistry>(
        http,
        "/v2/registries",
        pick("registries"),
      );
      return;
    } catch {
      // fall through to the legacy endpoint
    }

    const body = await http.get<{ registry?: DoRegistry }>("/v2/registry");
    inventory.registries = body.registry ? [body.registry] : [];
  },
};

/**
 * Spaces.
 *
 * Opt-in and bucket-scoped by design. DigitalOcean's v2 API cannot list buckets, so
 * the bucket list comes from `SPACES_BUCKETS` (region-qualified) rather than from
 * discovery. Without that configuration the collector declares itself unavailable and
 * the run reports partial, which is the honest description of an inventory that
 * cannot see object storage.
 *
 * If a key pair is supplied it is *verified* before anything else happens: a key with
 * account-wide or write access is refused outright rather than used. Detection itself
 * is an anonymous probe and needs no credential at all.
 */
export function createSpacesCollector(options: {
  config?: SpacesConfig;
  fetcher?: Fetcher;
} = {}): Collector {
  return {
    name: "spaces",
    required: false,
    resourceTypes: ["digitalocean.space"],
    async run(http, inventory) {
      // Sample-data mode must not reach the network for the one collector that does
      // not route through `http`. Explicit options still win, so tests are unaffected.
      const recorded = dataSource() === "fixtures";
      const config = options.config ?? (recorded ? FIXTURE_SPACES : loadSpacesConfig());
      const fetcher = options.fetcher ?? (recorded ? fixtureSpacesFetcher : undefined);
      const mode = spacesMode(config);
      inventory.spacesMode = mode;

      if (mode === "unavailable") {
        throw new CollectorUnavailableError(
          "Spaces was not assessed. DigitalOcean's v2 API cannot list buckets or read their " +
            "ACLs -- that requires the S3-compatible API -- so buckets must be named explicitly. " +
            "Set SPACES_BUCKETS to a comma-separated list of region/bucket pairs " +
            '(for example "nyc3/assets,ams3/backups") to enable it.',
        );
      }

      let buckets = config.buckets;

      if (config.accessKeyId) {
        const verification = await verifySpacesKey(http, config.accessKeyId);
        if (!verification.ok) {
          // Refusing an over-privileged credential is the point, not an inconvenience.
          throw new CollectorUnavailableError(
            `The supplied Spaces key was refused: ${verification.problems.join(" ")}`,
          );
        }
        // Trust DigitalOcean's grants over the configured list: a bucket the key was
        // never granted cannot be assessed, whatever the configuration claims.
        const granted = new Set(verification.grantedBuckets);
        buckets = buckets.filter((bucket) => granted.has(bucket.name));
      }

      inventory.spaces = await probeBuckets(buckets, fetcher);
    },
  };
}

export const spacesCollector: Collector = createSpacesCollector();

/** Execution order: required collectors first, so a partial run still has the spine. */
export const COLLECTORS: readonly Collector[] = [
  projectsCollector,
  dropletsCollector,
  firewallsCollector,
  loadBalancersCollector,
  vpcsCollector,
  databasesCollector,
  kubernetesCollector,
  appsCollector,
  volumesCollector,
  registriesCollector,
  certificatesCollector,
  spacesCollector,
];
