/**
 * Port and CIDR interpretation for firewall rules.
 *
 * Two details here are easy to get wrong and both change findings materially.
 */

export interface PortRange {
  from: number;
  to: number;
  /** True when the rule opens every port for its protocol. */
  all: boolean;
}

/**
 * Parse a DigitalOcean firewall `ports` value.
 *
 * The field is a STRING, and the string "0" means *all ports for this protocol* --
 * not port zero. Reading it literally turns "every port is open to the internet" into
 * the far less alarming "port 0 is open", which is exactly backwards. ICMP rules also
 * always report "0".
 */
export function parsePorts(ports: string | undefined): PortRange {
  const value = (ports ?? "").trim();

  if (value === "" || value === "0" || value.toLowerCase() === "all") {
    return { from: 0, to: 65535, all: true };
  }

  const range = value.match(/^(\d+)\s*-\s*(\d+)$/);
  if (range) {
    const from = Number(range[1]);
    const to = Number(range[2]);
    return { from: Math.min(from, to), to: Math.max(from, to), all: false };
  }

  const single = Number(value);
  if (Number.isInteger(single) && single >= 0 && single <= 65535) {
    return { from: single, to: single, all: false };
  }

  // Unparseable: assume the widest interpretation rather than under-reporting.
  return { from: 0, to: 65535, all: true };
}

/**
 * Does this source admit the entire public internet?
 *
 * Deliberately strict: only the two literal "everything" CIDRs count. A rule allowing
 * `0.0.0.0/1` technically covers half the address space, but treating broad-but-not-
 * universal prefixes as "public" would produce findings we cannot defend with a
 * one-line explanation, and every finding here has to survive a reviewer asking
 * "prove it".
 */
export function isPublicInternetCidr(address: string): boolean {
  const value = address.trim();
  return value === "0.0.0.0/0" || value === "::/0";
}

export function anyPublicInternetSource(addresses: readonly string[] | undefined): string | null {
  return (addresses ?? []).find(isPublicInternetCidr) ?? null;
}

/** Ports whose exposure to the internet is materially worse than a web port. */
export const SENSITIVE_PORTS: ReadonlyMap<number, string> = new Map([
  [22, "SSH"],
  [23, "Telnet"],
  [135, "MSRPC"],
  [139, "NetBIOS"],
  [445, "SMB"],
  [1433, "Microsoft SQL Server"],
  [1521, "Oracle DB"],
  [2375, "Docker daemon (unencrypted)"],
  [2376, "Docker daemon"],
  [3306, "MySQL"],
  [3389, "RDP"],
  [5432, "PostgreSQL"],
  [5984, "CouchDB"],
  [6379, "Redis"],
  [7001, "Cassandra"],
  [8020, "Hadoop NameNode"],
  [9200, "Elasticsearch"],
  [9300, "Elasticsearch transport"],
  [11211, "Memcached"],
  [27017, "MongoDB"],
  [27018, "MongoDB shard"],
]);

/** Ports where a public listener is ordinary rather than alarming. */
const WEB_PORTS: ReadonlySet<number> = new Set([80, 443, 8080, 8443]);

export function isWebPort(port: number): boolean {
  return WEB_PORTS.has(port);
}

/**
 * Which sensitive services a range exposes.
 *
 * A range is used rather than a membership test because `1-65535` and `20-30` both
 * cover SSH and both need naming in the evidence.
 */
export function sensitivePortsInRange(range: PortRange): Array<{ port: number; service: string }> {
  const hits: Array<{ port: number; service: string }> = [];
  for (const [port, service] of SENSITIVE_PORTS) {
    if (port >= range.from && port <= range.to) hits.push({ port, service });
  }
  return hits;
}

/** Human-readable rendering of a range for finding text. */
export function describePorts(range: PortRange, protocol: string): string {
  if (range.all) return `all ${protocol.toUpperCase()} ports`;
  if (range.from === range.to) return `${protocol.toUpperCase()} port ${range.from}`;
  return `${protocol.toUpperCase()} ports ${range.from}-${range.to}`;
}
