import { desc } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import { cloudAccounts } from "../db/schema";
import { listFindings } from "../data/queries";
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

  // Reuse the exposures page's own query -- same severity ordering, same filters -- so the
  // download and the screen can never disagree on which findings are current.
  const rows = listFindings(account.id, filters, db);

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
