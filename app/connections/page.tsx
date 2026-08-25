import Link from "next/link";
import { connectionState } from "../../src/connection/state";
import { oauthConfig } from "../../src/oauth/digitalocean";
import { hasMasterKey } from "../../src/oauth/crypto";
import { dataSource } from "../../src/lib/env";
import { counts, getAccount } from "../../src/data/queries";
import { DisconnectButton } from "../disconnect-button";

export const dynamic = "force-dynamic";

const REDIRECT_REASONS: Record<string, string> = {
  not_connected:
    "Nothing is connected yet. Choose how this scanner should authenticate to DigitalOcean — " +
    "the rest of the app stays hidden until it can actually read your account.",
  never_synced:
    "The credential works, but no snapshot has been built from it yet. Run a sync and the " +
    "rest of the app opens up.",
  disconnected:
    "Disconnected. The stored credential and everything synced from it have been deleted. " +
    "Connect again to start over.",
};

/** Off until proven on. */
function StatusRow({ state }: { state: ReturnType<typeof connectionState> }) {
  const tone =
    state.stage === "ready"
      ? { dot: "bg-ok", label: "Connected", text: "text-ok" }
      : state.stage === "connected_unsynced"
        ? { dot: "bg-medium", label: "Connected, not synced", text: "text-medium" }
        : { dot: "bg-rule", label: "Not connected", text: "text-faint" };

  return (
    <div className="panel flex flex-wrap items-center gap-x-5 gap-y-2 px-4 py-3">
      <span className="flex items-center gap-2">
        <span className={`inline-block h-2 w-2 rounded-full ${tone.dot}`} aria-hidden="true" />
        <span className={`text-sm font-medium ${tone.text}`}>{tone.label}</span>
      </span>

      {state.source !== "none" && (
        <span className="text-[0.8rem] text-muted">
          via{" "}
          <span className="font-mono">
            {state.source === "oauth" ? "OAuth" : "access token"}
          </span>
        </span>
      )}
      {state.teamName && <span className="text-[0.8rem] text-ink">{state.teamName}</span>}
      {state.grantedScopes && (
        <span className="font-mono text-[0.72rem] text-faint">{state.grantedScopes}</span>
      )}

      {state.stage === "ready" && (
        <Link href="/" className="ml-auto text-sm font-medium text-accent hover:underline">
          Open the assistant →
        </Link>
      )}
    </div>
  );
}

export default async function ConnectionMethodPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const { reason } = await searchParams;
  const explanation = reason ? REDIRECT_REASONS[reason] : undefined;

  const state = connectionState();
  const account = getAccount();
  const summary = account
    ? counts(account.id)
    : { resources: 0, findings: 0 };
  const oauthReady = Boolean(oauthConfig()) && hasMasterKey();
  const usingFixtures = dataSource() === "fixtures";

  return (
    <div className="max-w-5xl space-y-8">
      {explanation && (
        <div className="panel border-dashed px-4 py-3">
          <p className="text-sm font-medium text-ink">Connect first</p>
          <p className="mt-0.5 text-sm text-muted">{explanation}</p>
        </div>
      )}

      <header className="max-w-2xl">
        <div className="eyebrow mb-2">Connection</div>
        <h1 className="text-2xl font-semibold tracking-tight">
          How should this scanner authenticate to DigitalOcean?
        </h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          Both grant the same read access, so the scanner sees the same account either way.
          What differs is who creates the credential, how long it lives, and whether you can
          be sure it is read-only.
        </p>
      </header>

      <StatusRow state={state} />

      {state.stage !== "disconnected" && (
        <DisconnectButton counts={{ resources: summary.resources, findings: summary.findings }} />
      )}

      <div className="grid gap-4 md:grid-cols-2">
        <div className="panel flex flex-col p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow text-accent">Recommended</div>
              <h2 className="mt-2 text-lg font-semibold">OAuth</h2>
            </div>
            {state.source === "oauth" && (
              <span className="rounded border border-ok/30 bg-ok/5 px-2 py-0.5 text-[0.72rem] font-medium text-ok">
                active
              </span>
            )}
          </div>

          <p className="mt-3 text-sm leading-relaxed text-muted">
            You approve access on DigitalOcean&apos;s own consent screen. No credential is
            typed into this app, and the scope is fixed by us rather than chosen by you.
          </p>

          <dl className="mt-5 space-y-2.5 border-t border-rule pt-4 text-[0.82rem]">
            <div>
              <dt className="eyebrow">User experience</dt>
              <dd className="mt-0.5 text-muted">
                One click, then approve. Nothing to copy, paste, or store yourself. Syncing
                starts on its own once you return.
              </dd>
            </div>
            <div>
              <dt className="eyebrow">Security</dt>
              <dd className="mt-0.5 text-muted">
                The app requests the scope, so over-granting is impossible. Expires after 30
                days. Revocable from your DigitalOcean account settings at any time.
              </dd>
            </div>
            <div>
              <dt className="eyebrow">Implementation cost</dt>
              <dd className="mt-0.5 text-muted">
                Higher. A registered application, callback route, single-use state, token
                exchange, and encrypted storage — the token arrives at runtime, so it must be
                persisted rather than read from the environment.
              </dd>
            </div>
          </dl>

          <div className="mt-auto pt-5">
            {oauthReady ? (
              <a href="/api/connection/oauth/start" className="btn-primary">
                Connect with DigitalOcean
              </a>
            ) : (
              <div className="text-[0.8rem] text-muted">
                <p className="font-medium text-ink">Needs configuration</p>
                <p className="mt-0.5">
                  Set{" "}
                  <span className="font-mono">
                    {!oauthConfig() ? "DIGITALOCEAN_CLIENT_SECRET" : "TOKEN_MASTER_KEY"}
                  </span>{" "}
                  in <span className="font-mono">.env</span> and restart.
                </p>
              </div>
            )}
          </div>
        </div>

        <div className="panel flex flex-col p-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow">Simplest</div>
              <h2 className="mt-2 text-lg font-semibold">Personal access token</h2>
            </div>
            {state.source === "environment" && (
              <span className="rounded border border-ok/30 bg-ok/5 px-2 py-0.5 text-[0.72rem] font-medium text-ok">
                active
              </span>
            )}
          </div>

          <p className="mt-3 text-sm leading-relaxed text-muted">
            You create a read-only token in the DigitalOcean console and place it in the
            server environment. It is never written to the database or returned to the browser.
          </p>

          <dl className="mt-5 space-y-2.5 border-t border-rule pt-4 text-[0.82rem]">
            <div>
              <dt className="eyebrow">User experience</dt>
              <dd className="mt-0.5 text-muted">
                Several manual steps and a server restart. Workable for an operator, poor for
                a customer.
              </dd>
            </div>
            <div>
              <dt className="eyebrow">Security</dt>
              <dd className="mt-0.5 text-muted">
                You choose the scope, and the console makes Full Access the easy option.
                DigitalOcean exposes no way to introspect a token, so this app{" "}
                <span className="text-ink">cannot verify the one it holds is read-only</span>.
                No expiry unless you set one.
              </dd>
            </div>
            <div>
              <dt className="eyebrow">Implementation cost</dt>
              <dd className="mt-0.5 text-muted">
                Almost none. Read one environment variable. No storage, no encryption, no
                callback, nothing persisted.
              </dd>
            </div>
          </dl>

          <div className="mt-auto pt-5">
            <Link href="/connections/api-token" className="btn-quiet">
              Use an access token
            </Link>
          </div>
        </div>
      </div>

      <section className="max-w-3xl border-l-2 border-accent pl-4">
        <div className="eyebrow">The tradeoff in one line</div>
        <p className="mt-1 text-sm leading-relaxed text-muted">
          A token is cheaper to build and worse to hold. OAuth costs a callback route and an
          encrypted column, and buys you certainty about what you were granted. For a scanner
          that only ever reads, being unable to prove your own credential is read-only is the
          part that matters.
        </p>
      </section>

      {usingFixtures && (
        <p className="text-[0.78rem] text-faint">
          Sample-data mode is on, so the app works without either credential. Set{" "}
          <span className="font-mono">DATA_SOURCE=live</span> to scan a real account.
        </p>
      )}
    </div>
  );
}
