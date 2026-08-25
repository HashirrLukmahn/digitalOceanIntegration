import { NextResponse } from "next/server";
import { connectionState } from "../../../src/connection/state";
import { digitalOceanCredential } from "../../../src/do/credential";
import { getOAuthConnection } from "../../../src/oauth/digitalocean";
import { getAccount, getLatestRun } from "../../../src/data/queries";
import { apiBaseUrl, dataSource } from "../../../src/lib/env";
import { tokenFingerprint } from "../../../src/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Readiness. Is the stored credential still usable?
 *
 * Unlike /api/health this does call DigitalOcean — one cheap read of /v2/account,
 * which is the only way to find out whether a token has been revoked. DigitalOcean
 * sends no notification when a user revokes access, so asking is the only mechanism
 * available.
 *
 * `?probe=false` skips that call when you only want the local view.
 */
export async function GET(request: Request) {
  const probe = new URL(request.url).searchParams.get("probe") !== "false";
  const state = connectionState();
  const account = getAccount();
  const run = account ? getLatestRun(account.id) : null;
  const oauth = getOAuthConnection();

  const body: Record<string, unknown> = {
    connection: {
      stage: state.stage,
      source: state.source,
      team: state.teamName,
      // Enough to tell two credentials apart, useless to anyone who reads it.
      tokenFingerprint: tokenFingerprint(digitalOceanCredential()),
      grantedScopes: state.grantedScopes,
      expiresAt: oauth?.expiresAt?.toISOString() ?? null,
    },
    lastSync: run
      ? {
          status: run.status,
          startedAt: run.startedAt.toISOString(),
          resources: run.resourcesCount,
          findings: run.findingsCount,
        }
      : null,
    mode: dataSource(),
  };

  if (!probe || dataSource() === "fixtures") {
    return NextResponse.json({ ...body, credential: { checked: false } });
  }

  const token = digitalOceanCredential();
  if (!token) {
    return NextResponse.json(
      { ...body, credential: { checked: true, valid: false, reason: "no_credential" } },
      { status: 503 },
    );
  }

  try {
    const response = await fetch(new URL("/v2/account", apiBaseUrl()), {
      headers: { authorization: `Bearer ${token}`, accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
    });

    // 401 is the revocation signal. 403 means the credential lives but is
    // under-scoped — a different problem with a different fix, so it is reported
    // separately rather than collapsed into "invalid".
    const valid = response.ok;
    const reason = response.ok
      ? null
      : response.status === 401
        ? "revoked_or_invalid"
        : response.status === 403
          ? "insufficient_scope"
          : `http_${response.status}`;

    return NextResponse.json(
      { ...body, credential: { checked: true, valid, reason, httpStatus: response.status } },
      { status: valid ? 200 : 503 },
    );
  } catch {
    // Could not reach DigitalOcean. That is not evidence the credential is bad.
    return NextResponse.json({
      ...body,
      credential: { checked: true, valid: null, reason: "unreachable" },
    });
  }
}
