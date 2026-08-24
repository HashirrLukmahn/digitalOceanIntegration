import type { DoHttp } from "./http";

/**
 * Spaces support.
 *
 * DigitalOcean's v2 API cannot list buckets or read their ACLs, so this module works
 * differently from every other collector. Two observations shape it:
 *
 *   1. Detecting whether a *named* bucket is public needs no credential at all. An
 *      unauthenticated request that succeeds is proof of public access by
 *      demonstration, which is stronger evidence than reading a configuration field.
 *   2. A credential is only needed to *enumerate* buckets -- and DigitalOcean appears
 *      to gate listing behind full access, which also grants delete.
 *
 * So the bucket list comes from configuration, detection is an anonymous probe, and
 * the optional key pair exists to be *checked* rather than used: if a customer hands
 * over a key broader than read-on-named-buckets, we refuse it rather than quietly
 * holding a credential that can delete their data.
 */

export interface SpacesBucketRef {
  region: string;
  name: string;
}

export interface SpacesConfig {
  buckets: SpacesBucketRef[];
  accessKeyId?: string;
  secretAccessKey?: string;
}

export type SpacesMode = "unavailable" | "probe_only" | "authenticated";

/**
 * Parse `SPACES_BUCKETS`, a comma-separated list of `region/bucket` pairs.
 *
 * Region qualification is required rather than inferred: Spaces endpoints are
 * regional and a bucket lives in exactly one region, so without it we would be
 * guessing or probing every region for every bucket.
 */
export function parseSpacesBuckets(raw: string | undefined): SpacesBucketRef[] {
  if (!raw?.trim()) return [];

  const buckets: SpacesBucketRef[] = [];
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;

    const slash = trimmed.indexOf("/");
    if (slash <= 0 || slash === trimmed.length - 1) {
      throw new Error(
        `Invalid SPACES_BUCKETS entry "${trimmed}". Expected region/bucket, for example "nyc3/assets".`,
      );
    }
    buckets.push({ region: trimmed.slice(0, slash), name: trimmed.slice(slash + 1) });
  }
  return buckets;
}

export function loadSpacesConfig(env: NodeJS.ProcessEnv = process.env): SpacesConfig {
  return {
    buckets: parseSpacesBuckets(env.SPACES_BUCKETS),
    accessKeyId: env.SPACES_ACCESS_KEY_ID?.trim() || undefined,
    secretAccessKey: env.SPACES_SECRET_ACCESS_KEY?.trim() || undefined,
  };
}

export function spacesMode(config: SpacesConfig): SpacesMode {
  if (config.buckets.length === 0) return "unavailable";
  return config.accessKeyId && config.secretAccessKey ? "authenticated" : "probe_only";
}

export function bucketEndpoint(bucket: SpacesBucketRef): string {
  return `https://${bucket.name}.${bucket.region}.digitaloceanspaces.com`;
}

// --------------------------------------------------------------------------------
// Least-privilege enforcement
// --------------------------------------------------------------------------------

export interface SpacesGrant {
  bucket?: string;
  permission?: string;
}

export interface KeyVerification {
  ok: boolean;
  /** Buckets the key is actually permitted to read, per DigitalOcean. */
  grantedBuckets: string[];
  problems: string[];
}

/**
 * Verify a supplied Spaces key is scoped to read on named buckets, and nothing more.
 *
 * We already hold the account's API token, and `/v2/spaces/keys` reports every key's
 * grants, so the constraint can be *enforced* rather than merely requested in the
 * documentation. A security tool that refuses a credential more powerful than it
 * needs is worth more than one that asks nicely and accepts whatever arrives.
 *
 * Requires the `spaces_key:read` scope.
 */
export async function verifySpacesKey(
  http: DoHttp,
  accessKeyId: string,
): Promise<KeyVerification> {
  const body = await http.get<{ keys?: Array<{ access_key?: string; grants?: SpacesGrant[] }> }>(
    "/v2/spaces/keys",
    { per_page: 200 },
  );

  const key = (body.keys ?? []).find((candidate) => candidate.access_key === accessKeyId);
  if (!key) {
    return {
      ok: false,
      grantedBuckets: [],
      problems: [
        "The supplied SPACES_ACCESS_KEY_ID does not exist on this account, or the API token " +
          "lacks the spaces_key:read scope needed to check it.",
      ],
    };
  }

  const grants = key.grants ?? [];
  const problems: string[] = [];
  const grantedBuckets: string[] = [];

  if (grants.length === 0) {
    problems.push("The key has no grants, so it cannot read anything.");
  }

  for (const grant of grants) {
    const permission = (grant.permission ?? "").toLowerCase();
    const bucket = grant.bucket ?? "";

    // An empty bucket means account-wide. Combined with any permission, that is
    // broader than this tool should ever hold.
    if (bucket === "") {
      problems.push(
        `Grant "${permission || "(empty)"}" applies to all buckets. This tool requires ` +
          "per-bucket grants; create a key limited to the specific buckets you want assessed.",
      );
      continue;
    }

    if (permission === "read") {
      grantedBuckets.push(bucket);
      continue;
    }

    problems.push(
      `Grant on "${bucket}" is "${permission}", which permits more than reading. ` +
        "This tool is read-only; create a key with read permission instead.",
    );
  }

  return { ok: problems.length === 0, grantedBuckets, problems };
}

// --------------------------------------------------------------------------------
// Public-read detection
// --------------------------------------------------------------------------------

export interface BucketProbe {
  bucket: SpacesBucketRef;
  endpoint: string;
  /** True when an unauthenticated request succeeded in listing the bucket. */
  publiclyListable: boolean;
  status: number | null;
  error?: string;
}

export type Fetcher = (url: string) => Promise<{ status: number; text: () => Promise<string> }>;

/**
 * Probe a bucket anonymously.
 *
 * A 200 to an unauthenticated list request means the bucket is readable by anyone on
 * the internet -- demonstrated rather than inferred. 403 and 401 mean access is
 * restricted, which is the desired state. Anything else is reported as inconclusive
 * rather than being rounded to "safe".
 */
export async function probeBucket(
  bucket: SpacesBucketRef,
  fetcher: Fetcher = (url) => fetch(url, { method: "GET", redirect: "manual" }),
): Promise<BucketProbe> {
  const endpoint = bucketEndpoint(bucket);
  // max-keys=1 keeps the response small; we only need the status.
  const url = `${endpoint}/?max-keys=1`;

  try {
    const response = await fetcher(url);
    return {
      bucket,
      endpoint,
      publiclyListable: response.status === 200,
      status: response.status,
    };
  } catch (error) {
    return {
      bucket,
      endpoint,
      publiclyListable: false,
      status: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function probeBuckets(
  buckets: readonly SpacesBucketRef[],
  fetcher?: Fetcher,
): Promise<BucketProbe[]> {
  const results: BucketProbe[] = [];
  for (const bucket of buckets) {
    results.push(await probeBucket(bucket, fetcher));
  }
  return results;
}
