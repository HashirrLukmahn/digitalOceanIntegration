import "server-only";
import { redirect } from "next/navigation";
import { credentialSource, type CredentialSource } from "../do/credential";
import { getOAuthConnection } from "../oauth/digitalocean";
import { getAccount, getLatestRun } from "../data/queries";

/**
 * Whether the app has anything to show, and why not when it doesn't.
 *
 * Everything that displays account data goes through `requireConnection()`. The
 * default is off: a scanner that renders empty tables before anything is connected
 * reads as "your account is clean" rather than "nothing has been scanned", and for a
 * security tool that false reassurance is the worst possible failure mode.
 */

export type ConnectionStage =
  /** No credential at all. Nothing can be done until one is chosen. */
  | "disconnected"
  /** Credential present, but no snapshot has been built from it yet. */
  | "connected_unsynced"
  /** Credential present and at least one sync has run. */
  | "ready";

export interface ConnectionState {
  stage: ConnectionStage;
  source: CredentialSource;
  teamName: string | null;
  lastSyncedAt: Date | null;
  /** Scopes DigitalOcean actually granted. OAuth only — a PAT cannot be introspected. */
  grantedScopes: string | null;
}

export function connectionState(): ConnectionState {
  const source = credentialSource();
  const oauth = source === "oauth" ? getOAuthConnection() : null;
  const account = getAccount();
  const run = account ? getLatestRun(account.id) : null;

  const stage: ConnectionStage =
    source === "none" ? "disconnected" : run ? "ready" : "connected_unsynced";

  return {
    stage,
    source,
    teamName: oauth?.teamName ?? account?.name ?? null,
    lastSyncedAt: account?.lastSyncedAt ?? null,
    grantedScopes: oauth?.grantedScopes || null,
  };
}

/**
 * Gate for every page that shows account data.
 *
 * Sends the user to choose a connection rather than rendering an empty shell. The
 * reason travels in the query string so the destination can explain what happened
 * instead of looking like a dead end.
 */
export function requireConnection(): ConnectionState {
  const state = connectionState();

  if (state.stage === "disconnected") redirect("/connections?reason=not_connected");
  if (state.stage === "connected_unsynced") redirect("/connections?reason=never_synced");

  return state;
}
