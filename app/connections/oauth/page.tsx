import Link from "next/link";
import { connectionState } from "../../../src/connection/state";
import { getOAuthConnection, oauthConfig } from "../../../src/oauth/digitalocean";
import { hasMasterKey } from "../../../src/oauth/crypto";

export const dynamic = "force-dynamic";

/** What went wrong, said plainly, with the thing to do about it. */
const ERRORS: Record<string, { title: string; detail: string }> = {
  invalid_state: {
    title: "That authorization expired",
    detail:
      "Authorizations are valid for thirty minutes and can only be used once. Signing in to " +
      "DigitalOcean first can use up that window. Start again — it should go straight through " +
      "now that you are signed in.",
  },
  invalid_callback: {
    title: "DigitalOcean sent an incomplete response",
    detail: "No authorization code came back. Start the connection again.",
  },
  declined: {
    title: "Authorization was declined",
    detail: "Nothing was connected. You can start again whenever you like.",
  },
  exchange_failed: {
    title: "The authorization code was rejected",
    detail:
      "DigitalOcean would not exchange the code for a token. This usually means the client " +
      "secret is wrong, or the callback URL registered on the application does not exactly " +
      "match the one this app sends.",
  },
  not_configured: {
    title: "OAuth is not configured",
    detail: "Set DIGITALOCEAN_CLIENT_ID and DIGITALOCEAN_CLIENT_SECRET in .env, then restart.",
  },
  no_master_key: {
    title: "No encryption key",
    detail:
      "An OAuth token has to be stored, so it has to be encrypted. Set TOKEN_MASTER_KEY in " +
      ".env and restart. Generate one with: openssl rand -base64 32",
  },
};

export default async function OAuthConnectionPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;
  const failure = params.error ? ERRORS[params.error] : undefined;
  const justConnected = params.connected === "1";

  const state = connectionState();
  const connection = getOAuthConnection();
  const configured = Boolean(oauthConfig());
  const ready = configured && hasMasterKey();

  return (
    <div className="max-w-3xl space-y-6">
      <header>
        <Link href="/connections" className="text-[0.8rem] text-accent hover:underline">
          ← Change connection method
        </Link>
        <h1 className="mt-3 text-lg font-semibold tracking-tight">Connect with OAuth</h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          You approve access on DigitalOcean&apos;s own consent screen. Nothing is typed into
          this app, and the scope is fixed by the request rather than chosen by you — so the
          credential cannot end up broader than a read-only scanner needs.
        </p>
      </header>

      {failure && (
        <div className="panel border-dashed px-4 py-3">
          <p className="text-sm font-medium text-critical">{failure.title}</p>
          <p className="mt-0.5 text-sm text-muted">{failure.detail}</p>
        </div>
      )}

      {justConnected && (
        <div className="panel px-4 py-3">
          <p className="text-sm font-medium text-ok">Connected</p>
          <p className="mt-0.5 text-sm text-muted">
            {params.sync_failed
              ? "The credential is stored and working, but the first sync did not finish. Run one from the syncs page."
              : `The first sync ran automatically${params.synced ? ` and finished ${params.synced}` : ""}.`}
          </p>
        </div>
      )}

      {connection ? (
        <section className="panel px-4 py-4">
          <div className="eyebrow mb-3">Current connection</div>
          <dl className="space-y-2 text-sm">
            <div className="flex gap-3">
              <dt className="w-32 flex-none text-faint">Team</dt>
              <dd>{connection.teamName ?? "—"}</dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-32 flex-none text-faint">Granted scope</dt>
              <dd className="font-mono text-[0.8rem]">{connection.grantedScopes || "—"}</dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-32 flex-none text-faint">Expires</dt>
              <dd className="font-mono text-[0.8rem]">
                {connection.expiresAt ? connection.expiresAt.toISOString().slice(0, 10) : "—"}
              </dd>
            </div>
            <div className="flex gap-3">
              <dt className="w-32 flex-none text-faint">Token</dt>
              <dd className="text-muted">Encrypted at rest. Never returned to the browser.</dd>
            </div>
          </dl>

          <div className="mt-4 flex flex-wrap gap-3 border-t border-rule pt-4">
            <a href="/api/connection/oauth/start" className="btn-quiet">
              Reconnect
            </a>
            {state.stage === "ready" && (
              <Link href="/" className="btn-primary">
                Open the assistant
              </Link>
            )}
          </div>
        </section>
      ) : (
        <section className="panel px-4 py-4">
          {ready ? (
            <>
              <p className="text-sm text-muted">
                You will be sent to DigitalOcean to approve read-only access, then returned
                here. The first sync starts on its own.
              </p>
              <a href="/api/connection/oauth/start" className="btn-primary mt-4">
                Connect with DigitalOcean
              </a>
            </>
          ) : (
            <>
              <p className="text-sm font-medium text-ink">Needs configuration</p>
              <p className="mt-0.5 text-sm text-muted">
                Set{" "}
                <span className="font-mono">
                  {!configured ? "DIGITALOCEAN_CLIENT_ID and DIGITALOCEAN_CLIENT_SECRET" : "TOKEN_MASTER_KEY"}
                </span>{" "}
                in <span className="font-mono">.env</span> and restart.
              </p>
            </>
          )}
        </section>
      )}

      <section className="text-[0.8rem] leading-relaxed text-faint">
        <p>
          The authorization code flow is the only one implemented. DigitalOcean also offers the
          implicit flow, which returns a live token in the URL fragment where it lands in
          browser history and referrer headers — there is no code path here that can produce
          one. Each authorization is single-use and valid for thirty minutes.
        </p>
      </section>
    </div>
  );
}
