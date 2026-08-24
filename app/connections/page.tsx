import { SyncButton, TestConnectionButton } from "../actions";
import { Coverage, Field, StatusPill, formatTime } from "../components";
import { getAccount, getLatestRun } from "../../src/data/queries";
import { dataSource, digitalOceanToken } from "../../src/lib/env";
import { loadSpacesConfig, spacesMode } from "../../src/do/spaces";
import { tokenFingerprint } from "../../src/lib/redact";

export const dynamic = "force-dynamic";

/**
 * The connection surface.
 *
 * There is deliberately no field to paste a token into. The credential is read from
 * the environment and never persisted, so offering a form would invite storing it --
 * and a form that accepts a secret and then throws it away is a confusing promise to
 * make. What the page does instead is show which credential is configured, prove it
 * works, and state exactly what it can and cannot reach.
 */
export default function ConnectionsPage() {
  const account = getAccount();
  const run = account ? getLatestRun(account.id) : null;
  const mode = dataSource();
  const token = digitalOceanToken();
  const spaces = loadSpacesConfig();
  const spacesState = spacesMode(spaces);

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">Connection</h1>
        <p className="mt-1 text-sm text-muted">
          Credentials are read from the environment at the moment of use. Nothing on this page is
          written to the database, the logs, or the export.
        </p>
      </div>

      <section className="panel px-4 py-4">
        <div className="grid gap-5 sm:grid-cols-3">
          <Field label="Mode">
            <span className="font-mono text-[0.8rem]">{mode}</span>
          </Field>
          <Field label="API token">
            {mode === "fixtures" ? (
              <span className="text-faint">not required in fixture mode</span>
            ) : token ? (
              <span className="font-mono text-[0.8rem]">{tokenFingerprint(token)}</span>
            ) : (
              <span className="text-critical">not set</span>
            )}
          </Field>
          <Field label="Team">
            {account ? account.name : <span className="text-faint">not yet identified</span>}
          </Field>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-rule pt-4">
          <TestConnectionButton />
          <SyncButton />
          <a href="/api/export" className="btn-quiet" download>
            Export JSON
          </a>
        </div>

        {mode === "live" && !token && (
          <p className="mt-4 text-sm text-critical">
            Set <span className="font-mono">DIGITALOCEAN_TOKEN</span> in{" "}
            <span className="font-mono">.env</span> to a read-only{" "}
            <span className="font-mono">api:read</span> personal access token, or start the app
            with <span className="font-mono">DATA_SOURCE=fixtures</span> to evaluate it without
            one.
          </p>
        )}
      </section>

      <section className="panel px-4 py-4">
        <h2 className="text-sm font-semibold">Object storage</h2>
        <p className="mt-1 text-sm text-muted">
          Spaces is assessed separately and is off by default. DigitalOcean&apos;s v2 API cannot
          list buckets or read their permissions, so buckets are named explicitly rather than
          discovered.
        </p>

        <div className="mt-4 grid gap-5 sm:grid-cols-3">
          <Field label="Status">
            <span className="font-mono text-[0.8rem]">{spacesState}</span>
          </Field>
          <Field label="Buckets configured">
            <span className="font-mono text-[0.8rem]">{spaces.buckets.length}</span>
          </Field>
          <Field label="Key supplied">
            <span className="font-mono text-[0.8rem]">{spaces.accessKeyId ? "yes" : "no"}</span>
          </Field>
        </div>

        {spacesState === "unavailable" ? (
          <p className="mt-4 text-sm text-muted">
            To enable it, set <span className="font-mono">SPACES_BUCKETS</span> to a
            comma-separated list of region-qualified buckets, for example{" "}
            <span className="font-mono">nyc3/assets,ams3/backups</span>. Public-read detection
            needs no credential at all.
          </p>
        ) : (
          <ul className="mt-4 space-y-1">
            {spaces.buckets.map((bucket) => (
              <li key={`${bucket.region}/${bucket.name}`} className="font-mono text-[0.78rem]">
                {bucket.region}/{bucket.name}
              </li>
            ))}
          </ul>
        )}

        {spaces.accessKeyId && (
          <p className="mt-4 text-sm text-muted">
            The supplied key is checked against its grants before use. A key with account-wide or
            write access is refused rather than used.
          </p>
        )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">Last sync</h2>
        {run ? (
          <>
            <div className="panel flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3">
              <StatusPill status={run.status} />
              <span className="font-mono text-[0.78rem] text-muted">
                {formatTime(run.startedAt)}
              </span>
              <span className="text-[0.8rem] text-muted">
                {run.resourcesCount} resources · {run.findingsCount} findings
              </span>
            </div>
            <Coverage coverage={run.coverageJson} />
          </>
        ) : (
          <div className="panel px-4 py-3 text-sm text-muted">
            No sync has run yet. Use <span className="font-medium text-ink">Sync now</span> to
            build the inventory.
          </div>
        )}
      </section>
    </div>
  );
}
