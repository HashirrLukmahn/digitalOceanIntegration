import { randomUUID } from "node:crypto";
import { and, desc, eq, inArray, isNull, lt } from "drizzle-orm";
import { getDb, type Database } from "../db/client";
import {
  cloudAccounts,
  cloudRelationships,
  cloudResources,
  exposureFindings,
  snapshots,
  syncRuns,
  type SyncCoverage,
  type SyncStatus,
} from "../db/schema";
import { assembleSnapshotDocument, SNAPSHOT_VERSION } from "../snapshot/document";
import {
  COLLECTORS,
  CollectorUnavailableError,
  emptyInventory,
  fetchTeam,
  type Collector,
  type RawInventory,
} from "../do/collectors";
import type { DoHttp } from "../do/http";
import { evaluateExposure } from "../exposure/engine";
import { logger } from "../lib/logger";
import { sanitizeError } from "../lib/redact";
import { normalizeInventory, resourceTypeFromExternalId } from "../normalize/resource";
import { deriveRelationships } from "../relationships/derive";

/**
 * Sync orchestration.
 *
 * The subtle part is reconciliation. `removed_at` and `resolved_at` mean "absent from
 * a later authoritative sync", and absence is only evidence of deletion if we
 * successfully listed that resource type. So reconciliation is scoped per resource
 * type: droplets are reconciled when the droplets collector succeeded, regardless of
 * what any other collector did.
 *
 * The alternative -- gating reconciliation on a fully clean run -- looks simpler and
 * is wrong twice over. One flaky optional collector would freeze deletion tracking
 * for the whole inventory, and because the Spaces collector can never succeed with a
 * personal access token, no run would ever qualify.
 */

export interface SyncOptions {
  http: DoHttp;
  db?: Database;
  collectors?: readonly Collector[];
  /** Injected in tests so timestamps are deterministic. */
  now?: () => Date;
}

export interface SyncResult {
  runId: string;
  accountId: string;
  status: SyncStatus;
  coverage: SyncCoverage;
  resourcesCount: number;
  relationshipsCount: number;
  findingsCount: number;
  error: string | null;
}

export async function runSync(options: SyncOptions): Promise<SyncResult> {
  const db = options.db ?? getDb();
  const collectors = options.collectors ?? COLLECTORS;
  const now = options.now ?? (() => new Date());
  const startedAt = now();

  // --- 1. Identify the account -------------------------------------------------
  let accountId: string;
  try {
    const team = await fetchTeam(options.http);
    accountId = upsertAccount(db, team, startedAt);
  } catch (error) {
    // We could not even establish who we are talking to. If a previous sync recorded
    // an account, attach a failed run to it so the failure is visible in the UI;
    // otherwise there is nothing to attach to and the caller reports it directly.
    const [existing] = db
      .select()
      .from(cloudAccounts)
      .orderBy(desc(cloudAccounts.updatedAt))
      .limit(1)
      .all();
    if (!existing) throw error;

    const runId = randomUUID();
    const message = sanitizeError(error);
    db.insert(syncRuns)
      .values({
        id: runId,
        accountId: existing.id,
        status: "failed",
        coverageJson: emptyCoverage(),
        error: message,
        startedAt,
        completedAt: now(),
      })
      .run();
    logger.error("Sync failed before the account could be identified", { error: message });
    return {
      runId,
      accountId: existing.id,
      status: "failed",
      coverage: emptyCoverage(),
      resourcesCount: 0,
      relationshipsCount: 0,
      findingsCount: 0,
      error: message,
    };
  }

  const runId = randomUUID();
  db.insert(syncRuns)
    .values({ id: runId, accountId, status: "running", coverageJson: emptyCoverage(), startedAt })
    .run();

  // --- 2. Collect ----------------------------------------------------------------
  const inventory: RawInventory = emptyInventory();
  const coverage = emptyCoverage();
  const authoritativeTypes = new Set<string>();
  const authoritativeKeys = new Set<string>();

  for (const collector of collectors) {
    try {
      const result = await collector.run(options.http, inventory);
      coverage.completedCollectors.push(collector.name);
      // Granular coverage keys: the collector name, its resource types, and any per-child
      // keys it reported (e.g. `database_firewall:<clusterId>`). A finding or edge records
      // the subset it read and reconciles only when every one of its keys is here.
      authoritativeKeys.add(collector.name);
      for (const type of collector.resourceTypes) {
        authoritativeTypes.add(type);
        authoritativeKeys.add(type);
      }
      for (const key of result?.coverageKeys ?? []) authoritativeKeys.add(key);
    } catch (error) {
      const message = sanitizeError(error);
      if (error instanceof CollectorUnavailableError) {
        coverage.unavailableCollectors.push({ collector: collector.name, message });
        logger.info("Collector unavailable", { collector: collector.name });
      } else {
        coverage.failedCollectors.push({ collector: collector.name, message });
        logger.warn("Collector failed", { collector: collector.name, error: message });
      }
    }
  }

  if (inventory.spacesMode !== "unavailable") {
    coverage.spaces = {
      mode: inventory.spacesMode,
      bucketsAssessed: inventory.spaces.length,
    };
  }

  coverage.authoritativeKeys = [...authoritativeKeys].sort();

  // --- 3. Normalize, relate, evaluate --------------------------------------------
  const resources = normalizeInventory(inventory);
  const relationships = deriveRelationships(inventory);
  const exposure = evaluateExposure(accountId, inventory);

  for (const resource of resources) {
    resource.isInternetExposed = exposure.exposedResourceIds.has(resource.externalId);
  }

  // --- 4. Persist ----------------------------------------------------------------
  const seenAt = now();
  // Computed here rather than after the transaction so the same status stamps both the
  // run row and the snapshot document written inside it. It depends only on coverage.
  const status = determineStatus(coverage, collectors.length);

  db.transaction((tx) => {
    for (const resource of resources) {
      tx.insert(cloudResources)
        .values({
          id: randomUUID(),
          accountId,
          externalId: resource.externalId,
          resourceType: resource.resourceType,
          name: resource.name,
          region: resource.region,
          state: resource.state,
          isInternetExposed: resource.isInternetExposed,
          sensitivity: resource.sensitivity,
          tagsJson: resource.tags,
          metadataJson: resource.metadata,
          firstSeenAt: seenAt,
          lastSeenAt: seenAt,
          removedAt: null,
        })
        .onConflictDoUpdate({
          target: [cloudResources.accountId, cloudResources.externalId],
          set: {
            name: resource.name,
            region: resource.region,
            state: resource.state,
            isInternetExposed: resource.isInternetExposed,
            sensitivity: resource.sensitivity,
            tagsJson: resource.tags,
            metadataJson: resource.metadata,
            lastSeenAt: seenAt,
            // A resource that came back is no longer removed.
            removedAt: null,
          },
        })
        .run();
    }

    // Relationships carry no history in the specification's schema, so the current
    // set is simply replaced. Scoped to the types this run was authoritative for, so
    // a failed collector does not delete edges it could not observe.
    const staleEdges = tx
      .select({
        id: cloudRelationships.id,
        source: cloudRelationships.sourceExternalId,
        target: cloudRelationships.targetExternalId,
      })
      .from(cloudRelationships)
      .where(eq(cloudRelationships.accountId, accountId))
      .all();

    const removableEdgeIds = staleEdges
      .filter((edge) => {
        const sourceType = resourceTypeFromExternalId(edge.source);
        const targetType = resourceTypeFromExternalId(edge.target);
        return (
          sourceType !== null &&
          targetType !== null &&
          authoritativeTypes.has(sourceType) &&
          authoritativeTypes.has(targetType)
        );
      })
      .map((edge) => edge.id);

    if (removableEdgeIds.length > 0) {
      tx.delete(cloudRelationships).where(inArray(cloudRelationships.id, removableEdgeIds)).run();
    }

    for (const edge of relationships) {
      tx.insert(cloudRelationships)
        .values({
          id: randomUUID(),
          accountId,
          sourceExternalId: edge.sourceExternalId,
          targetExternalId: edge.targetExternalId,
          relationship: edge.relationship,
          evidence: edge.evidence,
          metadataJson: edge.metadata,
        })
        .onConflictDoUpdate({
          target: [
            cloudRelationships.accountId,
            cloudRelationships.sourceExternalId,
            cloudRelationships.targetExternalId,
            cloudRelationships.relationship,
          ],
          set: { evidence: edge.evidence, metadataJson: edge.metadata },
        })
        .run();
    }

    for (const finding of exposure.findings) {
      tx.insert(exposureFindings)
        .values({
          id: finding.id,
          accountId,
          resourceExternalId: finding.resourceExternalId,
          kind: finding.kind,
          severity: finding.severity,
          title: finding.title,
          summary: finding.summary,
          evidenceJson: finding.evidence,
          coverageKeysJson: finding.coverageKeys ?? [],
          remediation: finding.remediation,
          firstSeenAt: seenAt,
          lastSeenAt: seenAt,
          resolvedAt: null,
        })
        .onConflictDoUpdate({
          target: exposureFindings.id,
          set: {
            severity: finding.severity,
            title: finding.title,
            summary: finding.summary,
            evidenceJson: finding.evidence,
            coverageKeysJson: finding.coverageKeys ?? [],
            remediation: finding.remediation,
            lastSeenAt: seenAt,
            // A finding observed again has not been resolved.
            resolvedAt: null,
          },
        })
        .run();
    }

    // --- 5. Reconcile, per authoritative resource type ---------------------------
    if (authoritativeTypes.size > 0) {
      const types = [...authoritativeTypes];

      tx.update(cloudResources)
        .set({ removedAt: seenAt })
        .where(
          and(
            eq(cloudResources.accountId, accountId),
            inArray(cloudResources.resourceType, types),
            lt(cloudResources.lastSeenAt, seenAt),
            isNull(cloudResources.removedAt),
          ),
        )
        .run();

      // A finding is resolvable when the data that would re-derive it was authoritative
      // this run yet the finding did not reappear. Findings that recorded `coverage_keys`
      // reconcile on those exact keys; the rest fall back to recovering a resource type
      // from the external id -- `do:dbaas:x` belongs to the database collector.
      const openFindings = tx
        .select({
          id: exposureFindings.id,
          resource: exposureFindings.resourceExternalId,
          coverageKeys: exposureFindings.coverageKeysJson,
        })
        .from(exposureFindings)
        .where(
          and(
            eq(exposureFindings.accountId, accountId),
            lt(exposureFindings.lastSeenAt, seenAt),
            isNull(exposureFindings.resolvedAt),
          ),
        )
        .all();

      const resolvableIds = openFindings
        .filter((row) =>
          isFindingResolvable(row.coverageKeys, row.resource, authoritativeKeys, authoritativeTypes),
        )
        .map((row) => row.id);

      if (resolvableIds.length > 0) {
        tx.update(exposureFindings)
          .set({ resolvedAt: seenAt })
          .where(inArray(exposureFindings.id, resolvableIds))
          .run();
      }
    }

    // --- 5b. Snapshot the post-reconciliation account view -----------------------
    // Read current state back *inside this transaction*, after every write and the
    // reconciliation above, so the snapshot is the merged view a partial run leaves
    // behind and can never disagree with the rows it describes. Retained rows (from a
    // failed collector) survive with removed_at / resolved_at still null.
    const snapshotResources = tx
      .select()
      .from(cloudResources)
      .where(and(eq(cloudResources.accountId, accountId), isNull(cloudResources.removedAt)))
      .all();
    const snapshotEdges = tx
      .select()
      .from(cloudRelationships)
      .where(eq(cloudRelationships.accountId, accountId))
      .all();
    const snapshotFindings = tx
      .select()
      .from(exposureFindings)
      .where(and(eq(exposureFindings.accountId, accountId), isNull(exposureFindings.resolvedAt)))
      .all();

    const document = assembleSnapshotDocument({
      syncRunId: runId,
      status,
      coverage,
      seenAt,
      generatedAt: seenAt.toISOString(),
      authoritativeKeys,
      resources: snapshotResources.map((row) => ({
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
        lastSeenAt: row.lastSeenAt,
      })),
      relationships: snapshotEdges.map((row) => ({
        sourceExternalId: row.sourceExternalId,
        targetExternalId: row.targetExternalId,
        relationship: row.relationship,
        evidence: row.evidence,
        metadata: row.metadataJson,
      })),
      findings: snapshotFindings.map((row) => ({
        fingerprint: row.id,
        resourceExternalId: row.resourceExternalId,
        kind: row.kind,
        severity: row.severity,
        title: row.title,
        summary: row.summary,
        evidence: row.evidenceJson,
        remediation: row.remediation,
        lastSeenAt: row.lastSeenAt,
        coverageKeys: row.coverageKeysJson,
      })),
    });

    tx.insert(snapshots)
      .values({
        id: randomUUID(),
        accountId,
        syncRunId: runId,
        snapshotVersion: SNAPSHOT_VERSION,
        status,
        documentJson: document,
        createdAt: seenAt,
      })
      .run();
  });

  // --- 6. Close out the run ------------------------------------------------------
  const completedAt = now();

  db.update(syncRuns)
    .set({
      status,
      resourcesCount: resources.length,
      relationshipsCount: relationships.length,
      findingsCount: exposure.findings.length,
      coverageJson: coverage,
      completedAt,
    })
    .where(eq(syncRuns.id, runId))
    .run();

  db.update(cloudAccounts)
    .set({ lastSyncedAt: completedAt, updatedAt: completedAt })
    .where(eq(cloudAccounts.id, accountId))
    .run();

  logger.info("Sync finished", {
    runId,
    status,
    resources: resources.length,
    relationships: relationships.length,
    findings: exposure.findings.length,
  });

  return {
    runId,
    accountId,
    status,
    coverage,
    resourcesCount: resources.length,
    relationshipsCount: relationships.length,
    findingsCount: exposure.findings.length,
    error: null,
  };
}

function emptyCoverage(): SyncCoverage {
  return { completedCollectors: [], failedCollectors: [], unavailableCollectors: [] };
}

/**
 * Whether an open finding should be marked resolved this run.
 *
 * A finding that recorded granular `coverageKeys` reconciles solely on them: every key it
 * depended on must have been authoritative this run, so a path finding that read
 * `firewalls` is not resolved merely because its resource type came back if the firewalls
 * collector failed. A finding with no keys keeps the coarser, resource-type behaviour.
 *
 * Pure and exported so the decision can be tested in isolation from the sync transaction.
 */
export function isFindingResolvable(
  coverageKeys: readonly string[],
  resourceExternalId: string,
  authoritativeKeys: ReadonlySet<string>,
  authoritativeTypes: ReadonlySet<string>,
): boolean {
  if (coverageKeys.length > 0) {
    return coverageKeys.every((key) => authoritativeKeys.has(key));
  }
  const type = resourceTypeFromExternalId(resourceExternalId);
  return type !== null && authoritativeTypes.has(type);
}

/**
 * A run is `completed` only when every collector ran. Because Spaces can never run
 * with a personal access token, a real sync of this app reports `partial` -- which is
 * the honest answer, and why coverage is surfaced prominently in the UI.
 */
function determineStatus(coverage: SyncCoverage, total: number): SyncStatus {
  if (coverage.completedCollectors.length === 0 && total > 0) return "failed";
  if (coverage.failedCollectors.length > 0 || coverage.unavailableCollectors.length > 0) {
    return "partial";
  }
  return "completed";
}

function upsertAccount(
  db: Database,
  team: { externalId: string; name: string },
  at: Date,
): string {
  const [existing] = db
    .select()
    .from(cloudAccounts)
    .where(
      and(eq(cloudAccounts.provider, "digitalocean"), eq(cloudAccounts.externalId, team.externalId)),
    )
    .limit(1)
    .all();

  if (existing) {
    db.update(cloudAccounts)
      .set({ name: team.name, updatedAt: at })
      .where(eq(cloudAccounts.id, existing.id))
      .run();
    return existing.id;
  }

  const id = randomUUID();
  db.insert(cloudAccounts)
    .values({
      id,
      provider: "digitalocean",
      externalId: team.externalId,
      name: team.name,
      createdAt: at,
      updatedAt: at,
    })
    .run();
  return id;
}
