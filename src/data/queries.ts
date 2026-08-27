import { and, count, desc, eq, inArray, isNull, like, or, sql, type SQL } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import { resourceTypeFromExternalId } from "../normalize/resource";
import {
  cloudAccounts,
  cloudRelationships,
  cloudResources,
  exposureFindings,
  syncRuns,
  type CloudRelationshipRow,
  type CloudResourceRow,
  type ExposureFindingRow,
} from "../db/schema";

/**
 * Read helpers for the pages.
 *
 * Every list function excludes removed or resolved rows by default: the interface
 * shows current state, and history is reachable deliberately rather than mixed in.
 */

export function getAccount() {
  return (
    getDb()
      .select()
      .from(cloudAccounts)
      .orderBy(desc(cloudAccounts.updatedAt))
      .limit(1)
      .all()[0] ?? null
  );
}

export function getLatestRun(accountId: string) {
  return (
    getDb()
      .select()
      .from(syncRuns)
      .where(eq(syncRuns.accountId, accountId))
      .orderBy(desc(syncRuns.startedAt))
      .limit(1)
      .all()[0] ?? null
  );
}

export function listRuns(accountId: string, limit = 50) {
  return getDb()
    .select()
    .from(syncRuns)
    .where(eq(syncRuns.accountId, accountId))
    .orderBy(desc(syncRuns.startedAt))
    .limit(limit)
    .all();
}

export interface InventoryFilters {
  type?: string;
  region?: string;
  exposure?: "exposed" | "not_exposed";
  sensitivity?: string;
  q?: string;
}

export function listResources(accountId: string, filters: InventoryFilters = {}): CloudResourceRow[] {
  const clauses: SQL[] = [eq(cloudResources.accountId, accountId), isNull(cloudResources.removedAt)];

  if (filters.type) clauses.push(eq(cloudResources.resourceType, filters.type));
  if (filters.region) clauses.push(eq(cloudResources.region, filters.region));
  if (filters.sensitivity) clauses.push(eq(cloudResources.sensitivity, filters.sensitivity as never));
  if (filters.exposure === "exposed") clauses.push(eq(cloudResources.isInternetExposed, true));
  if (filters.exposure === "not_exposed") clauses.push(eq(cloudResources.isInternetExposed, false));

  if (filters.q) {
    const term = `%${filters.q}%`;
    const search = or(
      like(cloudResources.name, term),
      like(cloudResources.externalId, term),
      like(cloudResources.region, term),
    );
    if (search) clauses.push(search);
  }

  return getDb()
    .select()
    .from(cloudResources)
    .where(and(...clauses))
    // Exposed first, then by type and name: the reader's question is "what is public".
    .orderBy(desc(cloudResources.isInternetExposed), cloudResources.resourceType, cloudResources.name)
    .all();
}

export function getResource(accountId: string, externalId: string): CloudResourceRow | null {
  return (
    getDb()
      .select()
      .from(cloudResources)
      .where(
        and(eq(cloudResources.accountId, accountId), eq(cloudResources.externalId, externalId)),
      )
      .limit(1)
      .all()[0] ?? null
  );
}

export interface ResourceEdges {
  outgoing: CloudRelationshipRow[];
  incoming: CloudRelationshipRow[];
}

export function getResourceEdges(accountId: string, externalId: string): ResourceEdges {
  const db = getDb();
  return {
    outgoing: db
      .select()
      .from(cloudRelationships)
      .where(
        and(
          eq(cloudRelationships.accountId, accountId),
          eq(cloudRelationships.sourceExternalId, externalId),
        ),
      )
      .all(),
    incoming: db
      .select()
      .from(cloudRelationships)
      .where(
        and(
          eq(cloudRelationships.accountId, accountId),
          eq(cloudRelationships.targetExternalId, externalId),
        ),
      )
      .all(),
  };
}

/** Names for the ids an edge points at, so the graph reads in words as well as URNs. */
export function resolveNames(accountId: string, externalIds: string[]): Map<string, string> {
  if (externalIds.length === 0) return new Map();
  const rows = getDb()
    .select({ externalId: cloudResources.externalId, name: cloudResources.name })
    .from(cloudResources)
    .where(
      and(eq(cloudResources.accountId, accountId), inArray(cloudResources.externalId, externalIds)),
    )
    .all();
  return new Map(rows.map((r) => [r.externalId, r.name]));
}

export interface FindingFilters {
  severity?: string;
  kind?: string;
  resourceType?: string;
}

const SEVERITY_ORDER = sql`case ${exposureFindings.severity}
  when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end`;

export function listFindings(
  accountId: string,
  filters: FindingFilters = {},
  db: Database = getDb(),
): ExposureFindingRow[] {
  const clauses: SQL[] = [
    eq(exposureFindings.accountId, accountId),
    isNull(exposureFindings.resolvedAt),
  ];
  if (filters.severity) clauses.push(eq(exposureFindings.severity, filters.severity as never));
  if (filters.kind) clauses.push(eq(exposureFindings.kind, filters.kind));

  const rows = db
    .select()
    .from(exposureFindings)
    .where(and(...clauses))
    .orderBy(SEVERITY_ORDER, exposureFindings.resourceExternalId)
    .all();

  if (!filters.resourceType) return rows;
  // The external id already encodes the type (`do:dbaas:x` -> database cluster), so
  // this is a string parse rather than a lookup per row.
  return rows.filter(
    (row) => resourceTypeFromExternalId(row.resourceExternalId) === filters.resourceType,
  );
}

export function findingsForResource(accountId: string, externalId: string): ExposureFindingRow[] {
  return getDb()
    .select()
    .from(exposureFindings)
    .where(
      and(
        eq(exposureFindings.accountId, accountId),
        eq(exposureFindings.resourceExternalId, externalId),
        isNull(exposureFindings.resolvedAt),
      ),
    )
    .orderBy(SEVERITY_ORDER)
    .all();
}

/** Distinct values for the filter controls, taken from what was actually synced. */
export function inventoryFacets(accountId: string) {
  const rows = getDb()
    .select({
      resourceType: cloudResources.resourceType,
      region: cloudResources.region,
      sensitivity: cloudResources.sensitivity,
    })
    .from(cloudResources)
    .where(and(eq(cloudResources.accountId, accountId), isNull(cloudResources.removedAt)))
    .all();

  return {
    types: [...new Set(rows.map((r) => r.resourceType))].sort(),
    regions: [...new Set(rows.map((r) => r.region).filter((r): r is string => Boolean(r)))].sort(),
    sensitivities: [...new Set(rows.map((r) => r.sensitivity))].sort(),
  };
}

export function findingFacets(accountId: string) {
  const rows = getDb()
    .select({ kind: exposureFindings.kind })
    .from(exposureFindings)
    .where(and(eq(exposureFindings.accountId, accountId), isNull(exposureFindings.resolvedAt)))
    .all();
  return { kinds: [...new Set(rows.map((r) => r.kind))].sort() };
}

export function counts(accountId: string) {
  const db = getDb();
  const live = and(eq(cloudResources.accountId, accountId), isNull(cloudResources.removedAt));

  const [resources] = db.select({ n: count() }).from(cloudResources).where(live).all();
  const [exposed] = db
    .select({ n: count() })
    .from(cloudResources)
    .where(and(live, eq(cloudResources.isInternetExposed, true)))
    .all();

  // One grouped pass rather than four counts plus a full fetch.
  const bySeverity = db
    .select({ severity: exposureFindings.severity, n: count() })
    .from(exposureFindings)
    .where(
      and(eq(exposureFindings.accountId, accountId), isNull(exposureFindings.resolvedAt)),
    )
    .groupBy(exposureFindings.severity)
    .all();

  const severity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const row of bySeverity) severity[row.severity] += row.n;

  return {
    resources: resources?.n ?? 0,
    exposed: exposed?.n ?? 0,
    findings: Object.values(severity).reduce((a, b) => a + b, 0),
    ...severity,
  };
}
