import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import * as schema from "../../src/db/schema";
import type { Database as Db } from "../../src/db/client";

/**
 * A migrated in-memory database.
 *
 * Tests run the checked-in migrations rather than pushing the schema, so a migration
 * that does not match the schema fails the suite instead of surfacing when the
 * evaluator runs `npm run db:migrate`.
 */
export function createTestDb(): { db: Db; close: () => void } {
  const sqlite = new Database(":memory:");
  sqlite.pragma("foreign_keys = ON");
  const db = drizzle(sqlite, { schema });
  migrate(db, { migrationsFolder: "./drizzle" });
  return { db, close: () => sqlite.close() };
}

/** A clock that advances only when a test says so, so timestamps are deterministic. */
export function fixedClock(startIso = "2026-01-01T00:00:00.000Z") {
  let current = new Date(startIso);
  return {
    now: () => new Date(current),
    advance(ms: number) {
      current = new Date(current.getTime() + ms);
    },
  };
}
