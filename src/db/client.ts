import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema";

/**
 * SQLite connection.
 *
 * Deliberately boring: one file, no server, no provisioning. WAL is enabled so a sync
 * writing in a route handler does not block the pages reading alongside it.
 */

export type Database = BetterSQLite3Database<typeof schema>;

export function databasePath(): string {
  return resolve(process.env.DATABASE_PATH ?? "./data/app.db");
}

let db: Database | undefined;

export function getDb(): Database {
  if (!db) {
    const path = databasePath();
    mkdirSync(dirname(path), { recursive: true });
    const sqlite = new Database(path);
    sqlite.pragma("journal_mode = WAL");
    sqlite.pragma("foreign_keys = ON");
    db = drizzle(sqlite, { schema });
  }
  return db;
}

/** Test seam: point the module at an in-memory or temporary database. */
export function setDb(next: Database | undefined): void {
  db = next;
}

export { schema };
