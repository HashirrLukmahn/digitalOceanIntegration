import { sql } from "drizzle-orm";
import {
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";
import type { SnapshotDocument } from "../snapshot/document";

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
  /**
   * Granular coverage keys this run was authoritative for -- the producer contract.
   *
   * A collector name is the whole-dataset key; a collector that does per-child work also
   * reports child keys like `database_firewall:<clusterId>` as each child call succeeds.
   * A finding records the subset it read as its `coverage_keys`, and reconciliation
   * resolves that finding only when every one of its keys is present here. This is finer
   * than the type-based reconciliation: a path finding that read `firewalls` is not
   * resolved just because its resource type came back, if the firewalls collector failed.
   */
  authoritativeKeys?: string[];
  /**
   * Which Spaces capability was available, when it ran at all.
   *
   * Its own field rather than a note appended to the collector name: "assessed 3
   * named buckets" and "enumerated the account" are different claims, and a reader
   * should not have to parse a string to tell them apart.
   */
  spaces?: { mode: string; bucketsAssessed: number };
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

/**
 * `trusts` is an internal-only relationship kind (see the canonical spec's "Internal
 * schema extensions"). It is stored and traversed like any other edge, but the frozen v1
 * JSON export never emits it -- `buildExport` filters it out, and the exported relationship
 * union stays the four public values. Adding it here rather than in the export type is what
 * keeps that distinction enforced by the compiler.
 */
export const RELATIONSHIPS = ["contains", "attached_to", "routes_to", "depends_on", "trusts"] as const;
export type RelationshipKind = (typeof RELATIONSHIPS)[number];

/** The subset of relationship kinds carried by the frozen v1 export. `trusts` is excluded. */
export const EXPORTED_RELATIONSHIPS = [
  "contains",
  "attached_to",
  "routes_to",
  "depends_on",
] as const;
export type ExportedRelationshipKind = (typeof EXPORTED_RELATIONSHIPS)[number];

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
    /**
     * The granular collector coverage keys this finding's derivation depended on.
     *
     * Internal only -- the frozen v1 export omits it. When non-empty, reconciliation
     * resolves this finding solely on these keys (every one must be authoritative),
     * replacing the coarser resource-type check for findings that set it. Empty means the
     * finding opts out and keeps type-based reconciliation.
     */
    coverageKeysJson: text("coverage_keys_json", { mode: "json" })
      .$type<string[]>()
      .notNull()
      .default(sql`'[]'`),
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

/**
 * One append-only snapshot document per sync run.
 *
 * Internal only -- it is not part of the frozen v1 export. It stores the
 * post-reconciliation account view (resources, relationships including `trusts`, findings,
 * and coverage, each item tagged observed-vs-retained) as an immutable evaluated-output
 * document. Written in the same transaction that updates current state, so it can never
 * disagree with the rows it describes. See src/snapshot/document.ts.
 */
export const snapshots = sqliteTable(
  "snapshots",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    syncRunId: text("sync_run_id")
      .notNull()
      .references(() => syncRuns.id, { onDelete: "cascade" }),
    /** Distinct from the export `schemaVersion`, so the stored shape can evolve freely. */
    snapshotVersion: text("snapshot_version").notNull(),
    status: text("status", { enum: SYNC_STATUSES }).notNull(),
    documentJson: text("document_json", { mode: "json" })
      .$type<SnapshotDocument>()
      .notNull(),
    createdAt: ts("created_at").notNull(),
  },
  (t) => [index("snapshots_account_created_idx").on(t.accountId, t.createdAt)],
);

export type CloudAccountRow = typeof cloudAccounts.$inferSelect;
export type SyncRunRow = typeof syncRuns.$inferSelect;
export type CloudResourceRow = typeof cloudResources.$inferSelect;
export type CloudRelationshipRow = typeof cloudRelationships.$inferSelect;
export type ExposureFindingRow = typeof exposureFindings.$inferSelect;
export type SnapshotRow = typeof snapshots.$inferSelect;

export const AGENT_OUTCOMES = ["completed", "incomplete", "failed"] as const;
export type AgentOutcome = (typeof AGENT_OUTCOMES)[number];

/**
 * One node in an agent's claimed path, together with the edge that reached it.
 *
 * A bare list of resource ids proves which *nodes* the agent touched but not which
 * *edge* it claims to have traversed between them, so a path could name two real
 * resources with no relationship between them and read as sound. Each hop therefore
 * carries the incoming edge, which is simultaneously the citation the grounding
 * validator checks against the stored graph.
 */
export interface AgentHop {
  /** The node reached at this hop. */
  resourceExternalId: string;
  /** Edge traversed to reach it. Absent on the entry hop, which has no incoming edge. */
  viaRelationship?: RelationshipKind;
  /**
   * Orientation of the stored (source -> target) edge relative to travel.
   * `outbound`: the previous node is the edge's source and this node its target.
   * `inbound`: the previous node is the edge's target and this node its source.
   */
  viaDirection?: "outbound" | "inbound";
  /** A supporting rule finding at this node, by kind, if the hop builds on one. */
  findingKind?: string;
}

/** A chain the agent claims, spanning two or more resources. */
export interface AgentFinding {
  title: string;
  severity: Severity;
  /** The ordered path: entry hop first, each later hop naming the edge that reached it. */
  hops: AgentHop[];
  reasoning: string;
  /** A concrete fix, required -- a claimed path with no remediation is not actionable. */
  remediation: string;
}

/**
 * One row per agent run.
 *
 * `incomplete` is a first-class outcome, not an error: when the step cap fires before
 * the agent calls its terminal tool there is no structured output at all, and the UI
 * must say "analysis incomplete" rather than "no problems found". Those mean opposite
 * things to a reader.
 *
 * One table, not three. `tool_calls_json` is enough to debug loop behaviour and
 * attribute cost; a normalised step table would never be queried.
 */
export const agentRuns = sqliteTable(
  "agent_runs",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    /** The sync run whose stored state the agent analysed, recorded so a run is auditable. */
    snapshotSyncRunId: text("snapshot_sync_run_id"),
    outcome: text("outcome", { enum: AGENT_OUTCOMES }).notNull(),
    steps: integer("steps").notNull().default(0),
    toolCallsJson: text("tool_calls_json", { mode: "json" })
      .$type<Array<{ toolName: string; input: unknown }>>()
      .notNull()
      .default(sql`'[]'`),
    findingsJson: text("findings_json", { mode: "json" })
      .$type<AgentFinding[]>()
      .notNull()
      .default(sql`'[]'`),
    /** Sanitized. */
    error: text("error"),
    startedAt: ts("started_at").notNull(),
    completedAt: ts("completed_at"),
  },
  (t) => [index("agent_runs_account_started_idx").on(t.accountId, t.startedAt)],
);

export type AgentRunRow = typeof agentRuns.$inferSelect;

/**
 * A saved conversation.
 *
 * Messages live as one JSON blob rather than a rows-per-message table: they are only
 * ever read and written whole, and a normalised table would buy nothing but joins.
 */
export const chatThreads = sqliteTable(
  "chat_threads",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id")
      .notNull()
      .references(() => cloudAccounts.id, { onDelete: "cascade" }),
    /** First words of the opening question. Enough to find a conversation again. */
    title: text("title").notNull(),
    messagesJson: text("messages_json", { mode: "json" })
      .$type<unknown[]>()
      .notNull()
      .default(sql`'[]'`),
    createdAt: ts("created_at").notNull(),
    updatedAt: ts("updated_at").notNull(),
  },
  (t) => [index("chat_threads_account_updated_idx").on(t.accountId, t.updatedAt)],
);

export type ChatThreadRow = typeof chatThreads.$inferSelect;

/**
 * Single-use CSRF state for the authorization code flow.
 *
 * Only the hash is stored, so a leaked database cannot be replayed against an
 * authorization still in flight.
 */
export const oauthStates = sqliteTable("oauth_states", {
  stateHash: text("state_hash").primaryKey(),
  redirectUri: text("redirect_uri").notNull(),
  createdAt: ts("created_at").notNull(),
  expiresAt: ts("expires_at").notNull(),
  consumedAt: ts("consumed_at"),
});

/**
 * The connected DigitalOcean account, when connected by OAuth.
 *
 * One row, pinned to a fixed id — this build is single-tenant, and a table that can
 * only hold one row is clearer than a table that could hold many but never does.
 */
export const oauthConnection = sqliteTable("oauth_connection", {
  id: text("id").primaryKey(),
  accessTokenCt: text("access_token_ct").notNull(),
  refreshTokenCt: text("refresh_token_ct"),
  expiresAt: ts("expires_at"),
  grantedScopes: text("granted_scopes").notNull().default(""),
  teamName: text("team_name"),
  teamUuid: text("team_uuid"),
  createdAt: ts("created_at").notNull(),
  updatedAt: ts("updated_at").notNull(),
});

export type OAuthConnectionRow = typeof oauthConnection.$inferSelect;
