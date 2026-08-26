import { and, desc, eq, isNull } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import {
  cloudAccounts,
  cloudRelationships,
  cloudResources,
  exposureFindings,
  syncRuns,
} from "../db/schema";
import type { CloudResource } from "../normalize/resource";

/**
 * The JSON export.
 *
 * This is the only compatibility requirement in the specification, so the shape is
 * reproduced exactly, including the two details that differ from our internal model:
 * findings expose `fingerprint` rather than `id`, and coverage has only two buckets,
 * so collectors we track as *unavailable* are reported as failed with their reason
 * intact.
 */

export interface ExportedRelationship {
  sourceExternalId: string;
  targetExternalId: string;
  relationship: "contains" | "attached_to" | "routes_to" | "depends_on";
  evidence: "provider_reported" | "derived";
  metadata: Record<string, unknown>;
}

export interface ExportedFinding {
  fingerprint: string;
  resourceExternalId: string;
  kind: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  remediation: string;
}

export interface DigitalOceanSecurityExport {
  schemaVersion: "1";
  generatedAt: string;
  account: { provider: "digitalocean"; externalId: string; name: string };
  resources: CloudResource[];
  relationships: ExportedRelationship[];
  findings: ExportedFinding[];
  coverage: {
    completedCollectors: string[];
    failedCollectors: Array<{ collector: string; message: string }>;
  };
}

export class NoAccountError extends Error {
  constructor() {
    super("No DigitalOcean account has been synced yet. Run a sync before exporting.");
    this.name = "NoAccountError";
  }
}

export interface BuildExportOptions {
  db?: Database;
  now?: () => Date;
  /**
   * Include resources and findings that a later sync showed to be gone.
   *
   * Default is false: the export represents current state, and shipping deleted
   * droplets to a downstream consumer without a deletion marker would be misleading.
   * The history stays in the database either way.
   */
  includeRemoved?: boolean;
}

export function buildExport(options: BuildExportOptions = {}): DigitalOceanSecurityExport {
  const db = options.db ?? getDb();
  const now = options.now ?? (() => new Date());

  // Same ordering as getAccount(): export what the interface is showing. An
  // unordered limit(1) returns whichever row was inserted first, so a database
  // holding both a fixture and a live sync exports the wrong account.
  const [account] = db
    .select()
    .from(cloudAccounts)
    .orderBy(desc(cloudAccounts.updatedAt))
    .limit(1)
    .all();
  if (!account) throw new NoAccountError();

  const resourceRows = db
    .select()
    .from(cloudResources)
    .where(
      options.includeRemoved
        ? eq(cloudResources.accountId, account.id)
        : and(eq(cloudResources.accountId, account.id), isNull(cloudResources.removedAt)),
    )
    .all();

  const relationshipRows = db
    .select()
    .from(cloudRelationships)
    .where(eq(cloudRelationships.accountId, account.id))
    .all();

  const findingRows = db
    .select()
    .from(exposureFindings)
    .where(
      options.includeRemoved
        ? eq(exposureFindings.accountId, account.id)
        : and(eq(exposureFindings.accountId, account.id), isNull(exposureFindings.resolvedAt)),
    )
    .all();

  // Coverage comes from the most recent run, which is what the resources reflect.
  const [latestRun] = db
    .select()
    .from(syncRuns)
    .where(eq(syncRuns.accountId, account.id))
    .orderBy(desc(syncRuns.startedAt))
    .limit(1)
    .all();

  const coverage = latestRun?.coverageJson ?? {
    completedCollectors: [],
    failedCollectors: [],
    unavailableCollectors: [],
  };

  return {
    schemaVersion: "1",
    generatedAt: now().toISOString(),
    account: {
      provider: "digitalocean",
      externalId: account.externalId,
      name: account.name,
    },
    resources: resourceRows.map((row) => ({
      provider: "digitalocean" as const,
      externalId: row.externalId,
      resourceType: row.resourceType,
      name: row.name,
      region: row.region,
      state: row.state,
      isInternetExposed: row.isInternetExposed,
      sensitivity: row.sensitivity,
      tags: row.tagsJson,
      metadata: row.metadataJson,
    })),
    // `trusts` is an internal-only relationship kind: it is stored and traversed, but the
    // frozen v1 export never carries it, and its relationship union stays the four public
    // values. Filtering here (rather than at the query) keeps the snapshot and graph, which
    // read the same table directly, able to see trust edges.
    relationships: relationshipRows
      .filter((row): row is typeof row & { relationship: ExportedRelationship["relationship"] } =>
        row.relationship !== "trusts",
      )
      .map((row) => ({
        sourceExternalId: row.sourceExternalId,
        targetExternalId: row.targetExternalId,
        relationship: row.relationship,
        evidence: row.evidence,
        metadata: row.metadataJson,
      })),
    findings: findingRows.map((row) => ({
      fingerprint: row.id,
      resourceExternalId: row.resourceExternalId,
      kind: row.kind,
      severity: row.severity,
      title: row.title,
      summary: row.summary,
      evidence: row.evidenceJson,
      remediation: row.remediation,
    })),
    coverage: {
      completedCollectors: coverage.completedCollectors,
      // The export schema has no "unavailable" bucket, so a collector that can never
      // run is reported as failed -- with the reason preserved so the distinction is
      // still legible to whoever reads the file.
      failedCollectors: [
        ...coverage.failedCollectors,
        ...(coverage.unavailableCollectors ?? []).map((entry) => ({
          collector: entry.collector,
          message: `unavailable: ${entry.message}`,
        })),
      ],
    },
  };
}
