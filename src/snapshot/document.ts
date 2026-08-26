import type { SyncCoverage, SyncStatus } from "../db/schema";
import type { CloudResource } from "../normalize/resource";
import { resourceTypeFromExternalId } from "../normalize/resource";

/**
 * The per-run snapshot document.
 *
 * One append-only, sanitized, versioned document is written per sync (see
 * `ENGINE-HARDENING-PLAN.md` and the canonical spec's "Internal schema extensions"). It is
 * three things at once, and it helps to keep them straight:
 *
 *   - The *post-reconciliation account view*: the merged current state a partial run leaves
 *     behind -- freshly observed rows plus last-known-good rows retained from a failed
 *     collector -- which is exactly what the UI and tables show. Every item is tagged
 *     `observed` or `retained` so a reader can tell a live value from a carried-over one.
 *   - An *immutable evaluated-output document*, not a replay input: it stores normalized
 *     output (resources, relationships including `trusts`, findings with their evidence and
 *     severity derivation, coverage), never the raw provider objects a rule read, so it
 *     cannot leak an App spec or a plaintext env var and does not promise to re-derive
 *     findings from scratch.
 *   - The internal artifact the graph and history read. It is versioned with
 *     `snapshotVersion`, distinct from the frozen export `schemaVersion`, and -- unlike the
 *     v1 export -- it carries the internal `trusts` edge and per-item `coverageKeys`.
 */

export const SNAPSHOT_VERSION = "1";

export type SnapshotFreshness = "observed" | "retained";

export interface SnapshotResource extends CloudResource {
  /** Observed this run, or retained from a prior run because its collector did not succeed. */
  freshness: SnapshotFreshness;
  /** The coverage keys this resource belongs to. */
  coverageKeys: string[];
}

export interface SnapshotRelationship {
  sourceExternalId: string;
  targetExternalId: string;
  relationship: string;
  evidence: string;
  metadata: Record<string, unknown>;
  freshness: SnapshotFreshness;
  /** Every dataset this edge's derivation depended on; the edge is live only if all are fresh. */
  coverageKeys: string[];
}

export interface SnapshotFinding {
  fingerprint: string;
  resourceExternalId: string;
  kind: string;
  severity: string;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  remediation: string;
  freshness: SnapshotFreshness;
  coverageKeys: string[];
}

export interface SnapshotDocument {
  snapshotVersion: string;
  syncRunId: string;
  status: SyncStatus;
  generatedAt: string;
  /** The same coverage recorded on the run, including the granular authoritative keys. */
  coverage: SyncCoverage;
  resources: SnapshotResource[];
  /** Includes the internal `trusts` edge, which the frozen v1 export omits. */
  relationships: SnapshotRelationship[];
  findings: SnapshotFinding[];
}

/** The post-reconciliation rows the builder serializes, as read back from the database. */
export interface SnapshotInputResource extends CloudResource {
  lastSeenAt: Date;
}
export interface SnapshotInputRelationship {
  sourceExternalId: string;
  targetExternalId: string;
  relationship: string;
  evidence: string;
  metadata: Record<string, unknown>;
}
export interface SnapshotInputFinding {
  fingerprint: string;
  resourceExternalId: string;
  kind: string;
  severity: string;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  remediation: string;
  lastSeenAt: Date;
  coverageKeys: string[];
}

export interface AssembleSnapshotParams {
  syncRunId: string;
  status: SyncStatus;
  coverage: SyncCoverage;
  /** The run's write timestamp: an item observed this run has `lastSeenAt === seenAt`. */
  seenAt: Date;
  generatedAt: string;
  /** Granular keys authoritative this run, used to mark edge freshness. */
  authoritativeKeys: ReadonlySet<string>;
  resources: readonly SnapshotInputResource[];
  relationships: readonly SnapshotInputRelationship[];
  findings: readonly SnapshotInputFinding[];
}

/**
 * The coverage keys an edge's derivation depended on.
 *
 * An edge is a function of its two endpoints' datasets; a `trusts` edge additionally reads
 * the source cluster's per-child firewall data. Listing them lets the reader see a stale
 * `trusts` edge -- one carried over from a failed database-firewall call -- for what it is.
 */
export function edgeCoverageKeys(edge: SnapshotInputRelationship): string[] {
  const keys = new Set<string>();
  const sourceType = resourceTypeFromExternalId(edge.sourceExternalId);
  const targetType = resourceTypeFromExternalId(edge.targetExternalId);
  if (sourceType) keys.add(sourceType);
  if (targetType) keys.add(targetType);
  if (edge.relationship === "trusts") {
    // do:dbaas:<clusterId> -> database_firewall:<clusterId>
    const clusterId = edge.sourceExternalId.split(":").slice(2).join(":");
    if (clusterId) keys.add(`database_firewall:${clusterId}`);
  }
  return [...keys];
}

/**
 * Assemble the snapshot document from the post-reconciliation rows.
 *
 * Pure: rows in, document out, no I/O. The caller reads current state back inside the sync
 * transaction and hands it here, so the document and the rows it describes can never
 * disagree. Freshness is per item: a resource or finding is `observed` when it was written
 * this run (`lastSeenAt === seenAt`) and `retained` otherwise; an edge is `observed` only
 * when every one of its coverage keys was authoritative this run.
 */
export function assembleSnapshotDocument(params: AssembleSnapshotParams): SnapshotDocument {
  const observedAt = params.seenAt.getTime();

  const resources: SnapshotResource[] = params.resources.map((row) => ({
    provider: row.provider,
    externalId: row.externalId,
    resourceType: row.resourceType,
    name: row.name,
    region: row.region,
    state: row.state,
    isInternetExposed: row.isInternetExposed,
    sensitivity: row.sensitivity,
    tags: row.tags,
    metadata: row.metadata,
    freshness: row.lastSeenAt.getTime() === observedAt ? "observed" : "retained",
    coverageKeys: [row.resourceType],
  }));

  const relationships: SnapshotRelationship[] = params.relationships.map((edge) => {
    const coverageKeys = edgeCoverageKeys(edge);
    const fresh = coverageKeys.every((key) => params.authoritativeKeys.has(key));
    return {
      sourceExternalId: edge.sourceExternalId,
      targetExternalId: edge.targetExternalId,
      relationship: edge.relationship,
      evidence: edge.evidence,
      metadata: edge.metadata,
      freshness: fresh ? "observed" : "retained",
      coverageKeys,
    };
  });

  const findings: SnapshotFinding[] = params.findings.map((row) => {
    // A finding that opted out of granular keys falls back to its resource type, so every
    // snapshot finding still names at least the dataset it belongs to.
    const fallbackType = resourceTypeFromExternalId(row.resourceExternalId);
    const coverageKeys =
      row.coverageKeys.length > 0 ? row.coverageKeys : fallbackType ? [fallbackType] : [];
    return {
      fingerprint: row.fingerprint,
      resourceExternalId: row.resourceExternalId,
      kind: row.kind,
      severity: row.severity,
      title: row.title,
      summary: row.summary,
      evidence: row.evidence,
      remediation: row.remediation,
      freshness: row.lastSeenAt.getTime() === observedAt ? "observed" : "retained",
      coverageKeys,
    };
  });

  return {
    snapshotVersion: SNAPSHOT_VERSION,
    syncRunId: params.syncRunId,
    status: params.status,
    generatedAt: params.generatedAt,
    coverage: params.coverage,
    resources,
    relationships,
    findings,
  };
}
