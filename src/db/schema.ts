import { sql } from "drizzle-orm";
import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

/**
 * Local SQLite schema.
 *
 * Column names and semantics follow the work-trial specification exactly. Timestamps
 * are stored as epoch milliseconds (SQLite has no native date type) and surface as JS
 * `Date` objects; JSON columns are stored as TEXT and parsed by Drizzle.
 *
 * No table holds a credential. The DigitalOcean token is read from the environment at
 * call time and is never persisted -- see src/do/http.ts.
 */

const ts = (name: string) => integer(name, { mode: "timestamp_ms" });

/** One row for the connected DigitalOcean team. */
export const cloudAccounts = sqliteTable(
  "cloud_accounts",
  {
    id: text("id").primaryKey(),
    provider: text("provider").notNull().default("digitalocean"),
    /** Stable DigitalOcean team identifier (account.team.uuid). */
    externalId: text("external_id").notNull(),
    name: text("name").notNull(),
    /** Set by a successful or partial sync. */
    lastSyncedAt: ts("last_synced_at"),
    createdAt: ts("created_at")
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
    updatedAt: ts("updated_at")
      .notNull()
      .default(sql`(unixepoch() * 1000)`),
  },
  (t) => [uniqueIndex("cloud_accounts_provider_external_idx").on(t.provider, t.externalId)],
);

export const SYNC_STATUSES = ["running", "completed", "partial", "failed"] as const;
export type SyncStatus = (typeof SYNC_STATUSES)[number];

/**
 * Which collectors succeeded and which did not, for a single run.
 *
 * `unavailable` is kept separate from `failed` because the two mean different things
 * operationally: a failed collector might succeed on the next run, while an
 * unavailable one never will with the credential this app uses (see the Spaces
 * collector). Both are reported to the evaluator as failed collectors in the JSON
 * export, which has only the two buckets.
 */
export interface SyncCoverage {
  completedCollectors: string[];
  failedCollectors: Array<{ collector: string; message: string }>;
  unavailableCollectors: Array<{ collector: string; message: string }>;
}

/** One row per attempted inventory sync. */
export const syncRuns = sqliteTable(
  "sync_runs",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    status: text("status", { enum: SYNC_STATUSES }).notNull(),
    resourcesCount: integer("resources_count").notNull().default(0),
    relationshipsCount: integer("relationships_count").notNull().default(0),
    findingsCount: integer("findings_count").notNull().default(0),
    coverageJson: text("coverage_json", { mode: "json" })
      .$type<SyncCoverage>()
      .notNull()
      .default(sql`'{"completedCollectors":[],"failedCollectors":[],"unavailableCollectors":[]}'`),
    /** Sanitized terminal error. Never contains a token or an Authorization header. */
    error: text("error"),
    startedAt: ts("started_at").notNull(),
    completedAt: ts("completed_at"),
  },
  (t) => [index("sync_runs_account_started_idx").on(t.accountId, t.startedAt)],
);

export const SENSITIVITIES = ["none", "credential", "datastore"] as const;
export type Sensitivity = (typeof SENSITIVITIES)[number];

/** One row per current DigitalOcean resource. */
export const cloudResources = sqliteTable(
  "cloud_resources",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    /** Stable `do:<type>:<provider-id>` identifier. Also DigitalOcean's own URN format. */
    externalId: text("external_id").notNull(),
    resourceType: text("resource_type").notNull(),
    name: text("name").notNull(),
    region: text("region"),
    state: text("state"),
    /** Deterministic. Derived by the exposure engine, never by a language model. */
    isInternetExposed: integer("is_internet_exposed", { mode: "boolean" })
      .notNull()
      .default(false),
    sensitivity: text("sensitivity", { enum: SENSITIVITIES }).notNull().default("none"),
    tagsJson: text("tags_json", { mode: "json" })
      .$type<Record<string, string>>()
      .notNull()
      .default(sql`'{}'`),
    /**
     * Allowlisted provider metadata only. Built by copying permitted keys, never by
     * deleting forbidden ones -- see src/normalize/metadata-allowlist.ts.
     */
    metadataJson: text("metadata_json", { mode: "json" })
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'`),
    firstSeenAt: ts("first_seen_at").notNull(),
    lastSeenAt: ts("last_seen_at").notNull(),
    /** Set only when absent from a later *complete* sync. See src/sync/run.ts. */
    removedAt: ts("removed_at"),
  },
  (t) => [
    uniqueIndex("cloud_resources_account_external_idx").on(t.accountId, t.externalId),
    index("cloud_resources_type_idx").on(t.accountId, t.resourceType),
    index("cloud_resources_exposed_idx").on(t.accountId, t.isInternetExposed),
  ],
);

export const RELATIONSHIPS = ["contains", "attached_to", "routes_to", "depends_on"] as const;
export type RelationshipKind = (typeof RELATIONSHIPS)[number];

export const EVIDENCE_SOURCES = ["provider_reported", "derived"] as const;
export type EvidenceSource = (typeof EVIDENCE_SOURCES)[number];

/** Provider-reported or deterministically derived edges between resources. */
export const cloudRelationships = sqliteTable(
  "cloud_relationships",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    sourceExternalId: text("source_external_id").notNull(),
    targetExternalId: text("target_external_id").notNull(),
    relationship: text("relationship", { enum: RELATIONSHIPS }).notNull(),
    evidence: text("evidence", { enum: EVIDENCE_SOURCES }).notNull(),
    metadataJson: text("metadata_json", { mode: "json" })
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'`),
  },
  (t) => [
    uniqueIndex("cloud_relationships_unique_idx").on(
      t.accountId,
      t.sourceExternalId,
      t.targetExternalId,
      t.relationship,
    ),
    index("cloud_relationships_source_idx").on(t.accountId, t.sourceExternalId),
    index("cloud_relationships_target_idx").on(t.accountId, t.targetExternalId),
  ],
);

export const SEVERITIES = ["low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * One row per actionable exposure -- not one row per raw firewall rule.
 *
 * `id` is a stable fingerprint over (account, resource, kind, the configuration
 * element that must change), so a finding keeps its identity across syncs and
 * `first_seen_at` / `resolved_at` mean something. See src/exposure/fingerprint.ts.
 */
export const exposureFindings = sqliteTable(
  "exposure_findings",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    resourceExternalId: text("resource_external_id").notNull(),
    kind: text("kind").notNull(),
    severity: text("severity", { enum: SEVERITIES }).notNull(),
    title: text("title").notNull(),
    summary: text("summary").notNull(),
    /** The public IP, rule, port, or provider setting that proves the exposure. */
    evidenceJson: text("evidence_json", { mode: "json" })
      .$type<Record<string, unknown>>()
      .notNull()
      .default(sql`'{}'`),
    remediation: text("remediation").notNull(),
    firstSeenAt: ts("first_seen_at").notNull(),
    lastSeenAt: ts("last_seen_at").notNull(),
    /** Set only when absent from a later *complete* sync. */
    resolvedAt: ts("resolved_at"),
  },
  (t) => [
    index("exposure_findings_account_severity_idx").on(t.accountId, t.severity),
    index("exposure_findings_resource_idx").on(t.accountId, t.resourceExternalId),
  ],
);

export type CloudAccountRow = typeof cloudAccounts.$inferSelect;
export type SyncRunRow = typeof syncRuns.$inferSelect;
export type CloudResourceRow = typeof cloudResources.$inferSelect;
export type CloudRelationshipRow = typeof cloudRelationships.$inferSelect;
export type ExposureFindingRow = typeof exposureFindings.$inferSelect;
