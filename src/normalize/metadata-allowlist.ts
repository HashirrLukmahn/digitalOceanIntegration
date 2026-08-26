/**
 * The metadata sanitization boundary.
 *
 * `metadata_json` is built by *copying permitted keys*, never by deleting forbidden
 * ones. That direction matters: with a denylist, every field DigitalOcean adds in
 * future is exposed by default and stays exposed until somebody notices. With an
 * allowlist, a new field is invisible until a human decides otherwise. For a tool
 * that reads other people's cloud accounts, "invisible by default" is the only
 * defensible default.
 *
 * The denylist below is a second line of defence, not the control. If a key ever
 * appears in both, the denylist wins and the value is dropped -- so a careless
 * addition to an allowlist cannot leak a credential.
 */

/** Per-resource-type permitted keys, copied verbatim from the provider object. */
export const METADATA_ALLOWLIST: Readonly<Record<string, readonly string[]>> = {
  "digitalocean.project": ["purpose", "environment", "is_default", "description", "created_at"],
  "digitalocean.droplet": ["size_slug", "vpc_uuid", "created_at"],
  "digitalocean.firewall": ["created_at"],
  "digitalocean.load_balancer": ["network", "vpc_uuid", "redirect_http_to_https", "created_at"],
  "digitalocean.vpc": ["ip_range", "default", "description", "created_at"],
  "digitalocean.kubernetes_cluster": ["version", "vpc_uuid", "created_at"],
  "digitalocean.database_cluster": ["engine", "version", "num_nodes", "private_network_uuid", "created_at"],
  "digitalocean.app": ["created_at", "updated_at"],
  "digitalocean.container_registry": ["created_at", "storage_usage_bytes"],
  "digitalocean.volume": ["size_gigabytes", "filesystem_type", "created_at"],
  // `not_after` and `type` are copied via computed metadata in normalizeCertificate; the
  // allowlist keeps only the plainly-safe descriptive keys. `sha1_fingerprint` is a public
  // identifier, not a secret.
  "digitalocean.certificate": ["state", "not_after", "sha1_fingerprint", "dns_names", "created_at"],
  "digitalocean.space": [],
};

/**
 * Keys that must never reach the database or the export, whatever an allowlist says.
 *
 * Matching is case-insensitive and substring-based, so `ca_certificate`,
 * `certificatePem`, and `CERTIFICATE` are all caught by `certificate`.
 */
const DENIED_KEY_FRAGMENTS: readonly string[] = [
  "token",
  "password",
  "secret",
  "credential",
  "certificate",
  "private_key",
  "privatekey",
  "kubeconfig",
  "connection_string",
  "user_data",
  "userdata",
  "uri", // database connection URIs embed username and password
  "auth",
  "key_pair",
];

export function isDeniedKey(key: string): boolean {
  const lower = key.toLowerCase();
  return DENIED_KEY_FRAGMENTS.some((fragment) => lower.includes(fragment));
}

/**
 * Copy the allowlisted keys of `raw` for a given resource type.
 *
 * `undefined` and `null` values are omitted rather than stored, so metadata stays
 * readable instead of filling with nulls for fields the account does not use.
 */
export function pickAllowed(
  resourceType: string,
  raw: Record<string, unknown>,
): Record<string, unknown> {
  const allowed = METADATA_ALLOWLIST[resourceType] ?? [];
  const out: Record<string, unknown> = {};

  for (const key of allowed) {
    if (isDeniedKey(key)) continue; // denylist overrides a mistaken allowlist entry
    const value = raw[key];
    if (value === undefined || value === null) continue;
    out[key] = value;
  }

  return out;
}

/**
 * Merge computed metadata (addresses, related ids) over the allowlisted copy.
 *
 * Computed entries pass through the same denylist, so a future contributor cannot
 * route around the allowlist by adding a derived field with a dangerous name.
 */
export function withComputed(
  base: Record<string, unknown>,
  computed: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...base };
  for (const [key, value] of Object.entries(computed)) {
    if (isDeniedKey(key)) continue;
    if (value === undefined || value === null) continue;
    if (Array.isArray(value) && value.length === 0) continue;
    out[key] = value;
  }
  return out;
}
