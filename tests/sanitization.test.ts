import { describe, expect, it } from "vitest";
import {
  isDeniedKey,
  METADATA_ALLOWLIST,
  pickAllowed,
  withComputed,
} from "../src/normalize/metadata-allowlist";
import {
  normalizeDatabase,
  normalizeInventory,
  normalizeKubernetes,
} from "../src/normalize/resource";
import { emptyInventory } from "../src/do/collectors";
import { scrub, scrubString, tokenFingerprint } from "../src/lib/redact";

/**
 * The specification forbids credentials, connection strings, certificates, user data
 * and object data from reaching stored metadata. These tests attack that boundary
 * from both directions: raw objects stuffed with secrets, and the allowlist itself.
 */

const TOKEN = "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd";

describe("allowlist is default-deny", () => {
  it("drops every key that is not explicitly permitted", () => {
    const raw = {
      engine: "pg",
      version: "15",
      // None of the following are on the allowlist for this type.
      admin_password: "hunter2",
      internal_notes: "anything",
      surprise_new_field_from_a_future_api_version: "leaked?",
    };

    const result = pickAllowed("digitalocean.database_cluster", raw);

    expect(result).toEqual({ engine: "pg", version: "15" });
  });

  it("returns nothing for a resource type with no allowlist entry", () => {
    expect(pickAllowed("digitalocean.unknown_type", { anything: "value" })).toEqual({});
  });

  it("omits null and undefined rather than storing them", () => {
    const result = pickAllowed("digitalocean.droplet", {
      size_slug: "s-1vcpu-1gb",
      vpc_uuid: null,
      created_at: undefined,
    });
    expect(result).toEqual({ size_slug: "s-1vcpu-1gb" });
  });
});

describe("denylist overrides the allowlist", () => {
  it.each([
    "token",
    "access_token",
    "password",
    "admin_password",
    "client_secret",
    "ca_certificate",
    "certificatePem",
    "private_key",
    "kubeconfig",
    "connection_string",
    "user_data",
    "uri",
    "database_uri",
  ])("treats %s as denied", (key) => {
    expect(isDeniedKey(key)).toBe(true);
  });

  it.each(["engine", "version", "region", "size_slug", "vpc_uuid", "ip_range"])(
    "leaves %s permitted",
    (key) => {
      expect(isDeniedKey(key)).toBe(false);
    },
  );

  it("strips a dangerous key even if a computed field tries to add it", () => {
    const result = withComputed({ engine: "pg" }, { kubeconfig: "apiVersion: v1", host: "db.example" });
    expect(result).toEqual({ engine: "pg", host: "db.example" });
  });

  it("contains no denied key in any shipped allowlist", () => {
    // Guards against a future contributor allowlisting something dangerous.
    for (const [type, keys] of Object.entries(METADATA_ALLOWLIST)) {
      for (const key of keys) {
        expect(isDeniedKey(key), `${type}.${key} is on an allowlist but is a denied key`).toBe(false);
      }
    }
  });
});

describe("credentials never survive normalization", () => {
  it("keeps a database connection URI out of metadata", () => {
    const resource = normalizeDatabase({
      id: "db-1",
      name: "prod-pg",
      engine: "pg",
      version: "15",
      connection: {
        host: "prod-pg.db.ondigitalocean.com",
        port: 25060,
        user: "doadmin",
        password: "super-secret-password",
        uri: "postgresql://doadmin:super-secret-password@prod-pg.db.ondigitalocean.com:25060/defaultdb",
      },
    });

    const serialised = JSON.stringify(resource);
    expect(serialised).not.toContain("super-secret-password");
    expect(serialised).not.toContain("postgresql://");
    expect(serialised).not.toContain("doadmin");

    // The non-secret parts a reviewer actually needs are still there.
    expect(resource.metadata.public_host).toBe("prod-pg.db.ondigitalocean.com");
    expect(resource.metadata.public_port).toBe(25060);
  });

  it("keeps kubernetes credentials out of metadata", () => {
    const resource = normalizeKubernetes({
      id: "k8s-1",
      name: "prod",
      version: "1.31",
      endpoint: "https://k8s-1.k8s.ondigitalocean.com",
      // Fields a future API version might include on the cluster object.
      ...({
        kubeconfig: "apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: SECRET",
        ca_certificate: "-----BEGIN CERTIFICATE-----",
        auth_token: TOKEN,
      } as Record<string, unknown>),
    });

    const serialised = JSON.stringify(resource);
    expect(serialised).not.toContain("BEGIN CERTIFICATE");
    expect(serialised).not.toContain("certificate-authority-data");
    expect(serialised).not.toContain(TOKEN);
    expect(serialised).not.toContain("dop_v1_");

    // The endpoint is required as exposure evidence and is not a secret.
    expect(resource.metadata.endpoint).toBe("https://k8s-1.k8s.ondigitalocean.com");
  });

  it("survives a whole inventory stuffed with secrets", () => {
    const inventory = emptyInventory();
    inventory.databases = [
      {
        id: "db",
        name: "db",
        connection: { host: "h", uri: `postgresql://u:p@h/db?token=${TOKEN}` },
      },
    ];
    inventory.kubernetes = [
      { id: "k", name: "k", ...({ kubeconfig: TOKEN } as Record<string, unknown>) },
    ];

    const serialised = JSON.stringify(normalizeInventory(inventory));
    expect(serialised).not.toContain(TOKEN);
    expect(serialised).not.toContain("dop_v1_");
  });
});

describe("log and error scrubbing", () => {
  it("removes a personal access token from free text", () => {
    expect(scrubString(`request failed with ${TOKEN}`)).not.toContain(TOKEN);
  });

  it("removes an Authorization header value", () => {
    expect(scrubString(`authorization: Bearer ${TOKEN}`)).not.toContain(TOKEN);
  });

  it("removes credentials embedded in a connection URI", () => {
    const scrubbed = scrubString("postgresql://doadmin:hunter2@db.example.com:25060/defaultdb");
    expect(scrubbed).not.toContain("hunter2");
    expect(scrubbed).not.toContain("doadmin");
  });

  it("redacts secret-named keys anywhere in a nested object", () => {
    const result = scrub({ outer: { headers: { authorization: `Bearer ${TOKEN}` } } });
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  it("produces a fingerprint that cannot reconstruct the token", () => {
    const fingerprint = tokenFingerprint(TOKEN);
    expect(fingerprint).toBe("****abcd");
    expect(fingerprint).not.toContain("dop_v1_");
    expect(TOKEN).toContain(fingerprint!.replace("****", ""));
  });

  it("returns no fingerprint for a missing or implausibly short token", () => {
    expect(tokenFingerprint(undefined)).toBeNull();
    expect(tokenFingerprint("short")).toBeNull();
  });
});
