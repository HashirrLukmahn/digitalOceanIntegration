import { and, desc, eq } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import { cloudAccounts, snapshots } from "../db/schema";
import type { SnapshotDocument } from "../snapshot/document";
import { NoAccountError } from "./build";

/**
 * The point-in-time snapshot export.
 *
 * Unlike the v1 export and the exposures export -- which read *current* database state --
 * this reads one of the stored, immutable snapshot documents by `syncRunId` (or the latest
 * if none is given). It is how you export exactly what a given sync evaluated, after the
 * fact, without the current tables having moved underneath it. The document is the internal
 * post-reconciliation view (resources, relationships including `trusts`, findings, and
 * coverage, each item marked observed-vs-retained), sanitized and versioned by
 * `snapshotVersion` -- it is not the frozen v1 export contract.
 */

export class NoSnapshotError extends Error {
  constructor(syncRunId?: string) {
    super(
      syncRunId
        ? `No snapshot was stored for sync run ${syncRunId}.`
        : "No snapshot has been stored yet. Run a sync first.",
    );
    this.name = "NoSnapshotError";
  }
}

export interface LoadSnapshotExportOptions {
  db?: Database;
  /** The run to export. Omit to export the most recent snapshot for the current account. */
  syncRunId?: string;
}

export function loadSnapshotExport(options: LoadSnapshotExportOptions = {}): SnapshotDocument {
  const db = options.db ?? getDb();

  // Same account selection as the other exports and the UI: the most recently updated one.
  const [account] = db
    .select()
    .from(cloudAccounts)
    .orderBy(desc(cloudAccounts.updatedAt))
    .limit(1)
    .all();
  if (!account) throw new NoAccountError();

  const where = options.syncRunId
    ? and(eq(snapshots.accountId, account.id), eq(snapshots.syncRunId, options.syncRunId))
    : eq(snapshots.accountId, account.id);

  const [row] = db
    .select()
    .from(snapshots)
    .where(where)
    .orderBy(desc(snapshots.createdAt))
    .limit(1)
    .all();
  if (!row) throw new NoSnapshotError(options.syncRunId);

  return row.documentJson;
}
