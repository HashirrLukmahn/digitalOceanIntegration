import { NextResponse } from "next/server";
import { getDb } from "../../../src/db/client";
import { sql } from "drizzle-orm";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Liveness. Is this process able to serve requests?
 *
 * Deliberately makes no call to DigitalOcean. A health check that depends on a third
 * party reports your app as unhealthy during their outage, and whatever is watching
 * it — a load balancer, a supervisor, a deploy gate — then restarts or removes a
 * process that was working perfectly. Credential validity is a *readiness* question
 * and lives on /api/status.
 */
export async function GET() {
  try {
    getDb().run(sql`select 1`);
  } catch {
    return NextResponse.json({ status: "unhealthy", database: "unreachable" }, { status: 503 });
  }

  return NextResponse.json({
    status: "ok",
    database: "ok",
    uptimeSeconds: Math.round(process.uptime()),
  });
}
