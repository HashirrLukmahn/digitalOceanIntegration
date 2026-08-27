import { and, desc, eq, isNull, sql, type SQL } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import { cloudAccounts, exposureFindings } from "../db/schema";
import { resourceTypeFromExternalId } from "../normalize/resource";
import { NoAccountError } from "./build";

/**
 * The exposures-only JSON export.
 *
 * A convenience download distinct from the frozen v1 `DigitalOceanSecurityExport`: it
 * carries just the rule-engine findings, optionally filtered to what the user is currently
 * viewing on the exposures page, so a reader can hand a focused set (say, only the criticals)
 * to an agent without the full resource/relationship envelope. Because it is a separate
 * artifact it is versioned on its own key (`format`) and is not bound by the v1 contract.
 *
 * Each exposure keeps its `evidence` object verbatim, which is where confidence and the
 * severity rationale live -- so the file is self-explaining, not just a list of titles.
 */

export interface ExportedExposure {
  fingerprint: string;
  resourceExternalId: string;
  kind: string;
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  remediation: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface ExposuresExport {
  format: "digitalocean-exposures-export";
  version: "1";
  generatedAt: string;
  account: { provider: "digitalocean"; externalId: string; name: string };
  /** The filters applied when the file was built, so the reader knows the set is a subset. */
  filters: { severity: string | null; kind: string | null; resourceType: string | null };
  count: number;
  exposures: ExportedExposure[];
}

export interface BuildExposuresExportOptions {
  db?: Database;
  now?: () => Date;
  filters?: { severity?: string; kind?: string; resourceType?: string };
}

const SEVERITY_ORDER = sql`case ${exposureFindings.severity}
  when 'critical' then 0 when 'high' then 1 when 'medium' then 2 else 3 end`;

export function buildExposuresExport(options: BuildExposuresExportOptions = {}): ExposuresExport {
  const db = options.db ?? getDb();
  const now = options.now ?? (() => new Date());
  const filters = options.filters ?? {};

  // Same account selection as the full export and the UI: the most recently updated one.
  const [account] = db
    .select()
    .from(cloudAccounts)
    .orderBy(desc(cloudAccounts.updatedAt))
    .limit(1)
    .all();
  if (!account) throw new NoAccountError();

  const clauses: SQL[] = [
    eq(exposureFindings.accountId, account.id),
    // Only current (unresolved) findings, matching what the exposures page shows.
    isNull(exposureFindings.resolvedAt),
  ];
  if (filters.severity) clauses.push(eq(exposureFindings.severity, filters.severity as never));
  if (filters.kind) clauses.push(eq(exposureFindings.kind, filters.kind));

  let rows = db
    .select()
    .from(exposureFindings)
    .where(and(...clauses))
    .orderBy(SEVERITY_ORDER, exposureFindings.resourceExternalId)
    .all();

  // The external id encodes the type (`do:dbaas:x` -> database cluster), so this is a parse
  // rather than a per-row lookup -- identical to the exposures page's own filter.
  if (filters.resourceType) {
    rows = rows.filter(
      (row) => resourceTypeFromExternalId(row.resourceExternalId) === filters.resourceType,
    );
  }

  return {
    format: "digitalocean-exposures-export",
    version: "1",
    generatedAt: now().toISOString(),
    account: {
      provider: "digitalocean",
      externalId: account.externalId,
      name: account.name,
    },
    filters: {
      severity: filters.severity ?? null,
      kind: filters.kind ?? null,
      resourceType: filters.resourceType ?? null,
    },
    count: rows.length,
    exposures: rows.map((row) => ({
      fingerprint: row.id,
      resourceExternalId: row.resourceExternalId,
      kind: row.kind,
      severity: row.severity,
      title: row.title,
      summary: row.summary,
      evidence: row.evidenceJson,
      remediation: row.remediation,
      firstSeenAt: row.firstSeenAt.toISOString(),
      lastSeenAt: row.lastSeenAt.toISOString(),
    })),
  };
}
