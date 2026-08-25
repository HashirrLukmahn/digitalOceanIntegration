import "server-only";
import { getDb } from "../db/client";
import {
  agentRuns,
  chatThreads,
  cloudAccounts,
  cloudRelationships,
  cloudResources,
  exposureFindings,
  oauthStates,
  syncRuns,
} from "../db/schema";
import { disconnectOAuth } from "../oauth/digitalocean";

/**
 * End the connection and destroy what it produced.
 *
 * Two decisions worth stating, because both could reasonably have gone the other way.
 *
 * The stored OAuth token is deleted rather than marked inactive. A revoked credential
 * is useless to us and pure liability to keep, so there is nothing to gain by
 * retaining it.
 *
 * The snapshot goes too. It describes an account we are no longer connected to, and a
 * scanner that keeps showing findings after you disconnect is asserting things about
 * infrastructure it can no longer see. Stale security data is worse than none — it
 * reads as current.
 *
 * Conversations go too, and not by choice: `chat_threads` cascades from
 * `cloud_accounts`, so the database removes them the moment the account row goes. That
 * is the right behaviour anyway — a saved conversation cites resource ids that no
 * longer exist.
 *
 * Deliberately kept: nothing. This is a single-tenant tool with no audit requirement,
 * so "disconnect" means what it says.
 */
export interface DisconnectResult {
  removedOAuthToken: boolean;
  removedResources: number;
  removedFindings: number;
  removedSyncRuns: number;
  removedConversations: number;
}

export function disconnect(): DisconnectResult {
  const db = getDb();

  const before = {
    resources: db.select().from(cloudResources).all().length,
    findings: db.select().from(exposureFindings).all().length,
    runs: db.select().from(syncRuns).all().length,
    threads: db.select().from(chatThreads).all().length,
  };

  const hadOAuth = Boolean(
    db.select().from(cloudAccounts).all().length || db.select().from(oauthStates).all().length,
  );

  db.transaction((tx) => {
    disconnectOAuth();

    // Order matters only for readability; every child cascades from cloud_accounts,
    // but deleting explicitly makes the intent legible rather than implicit.
    tx.delete(exposureFindings).run();
    tx.delete(cloudRelationships).run();
    tx.delete(cloudResources).run();
    tx.delete(agentRuns).run();
    tx.delete(syncRuns).run();
    tx.delete(cloudAccounts).run();

    // Unfinished authorizations belong to a connection that no longer exists.
    tx.delete(oauthStates).run();
  });

  return {
    removedOAuthToken: hadOAuth,
    removedResources: before.resources,
    removedFindings: before.findings,
    removedSyncRuns: before.runs,
    removedConversations: before.threads,
  };
}
