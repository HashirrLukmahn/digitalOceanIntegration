import Link from "next/link";
import { getAccount } from "../../src/data/queries";
import { dataSource, digitalOceanToken } from "../../src/lib/env";

export const dynamic = "force-dynamic";

const REDIRECT_REASONS: Record<string, string> = {
  not_connected:
    "No DigitalOcean account is connected yet. Verify a connection and run a sync — the " +
    "assistant answers from the stored snapshot, so it needs one before it can say anything.",
  never_synced:
    "The connection works, but nothing has been synced. Run a sync to build the snapshot the " +
    "assistant reads from.",
};

export default async function ConnectionMethodPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const { reason } = await searchParams;
  const explanation = reason ? REDIRECT_REASONS[reason] : undefined;
  const account = getAccount();
  const mode = dataSource();
  const hasToken = Boolean(digitalOceanToken());

  return (
    <div className="max-w-5xl space-y-8">
      {explanation && (
        <div className="panel border-dashed px-4 py-3">
          <p className="text-sm font-medium text-ink">Connect before asking</p>
          <p className="mt-0.5 text-sm text-muted">{explanation}</p>
        </div>
      )}

      <header className="max-w-2xl">
        <div className="eyebrow mb-2">Connection / Choose a method</div>
        <h1 className="text-2xl font-semibold tracking-tight">
          How should DigitalOcean authorize this review?
        </h1>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          Both paths should request read-only access. The difference is who creates the
          credential and how this scanner receives it.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-2">
        <Link
          href="/connections/oauth"
          className="panel group flex min-h-[19rem] flex-col p-5 transition-colors hover:border-accent"
          aria-describedby="oauth-description"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow text-accent">Recommended for shared deployments</div>
              <h2 className="mt-2 text-lg font-semibold">OAuth</h2>
            </div>
            <span className="unknown">setup required</span>
          </div>

          <p id="oauth-description" className="mt-3 text-sm leading-relaxed text-muted">
            The user approves access in DigitalOcean. The application receives a time-limited
            token without asking the user to copy a credential.
          </p>

          <div className="my-5 border-y border-rule bg-paper/60 px-3 py-3">
            <div className="eyebrow mb-2">Authorization path</div>
            <div className="flex flex-wrap items-center gap-2 font-mono text-[0.78rem] text-ink">
              <span>browser</span>
              <span className="text-accent" aria-hidden="true">→</span>
              <span>DigitalOcean</span>
              <span className="text-accent" aria-hidden="true">→</span>
              <span>callback</span>
            </div>
          </div>

          <dl className="grid grid-cols-2 gap-3 text-[0.8rem]">
            <div>
              <dt className="eyebrow">Requested scope</dt>
              <dd className="mt-1 font-mono">api:read</dd>
            </div>
            <div>
              <dt className="eyebrow">Token lifecycle</dt>
              <dd className="mt-1">Expires and refreshes</dd>
            </div>
          </dl>

          <span className="mt-auto pt-5 text-sm font-medium text-accent group-hover:underline">
            Review OAuth setup →
          </span>
        </Link>

        <Link
          href="/connections/api-token"
          className="panel group flex min-h-[19rem] flex-col p-5 transition-colors hover:border-accent"
          aria-describedby="token-description"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="eyebrow">Available now</div>
              <h2 className="mt-2 text-lg font-semibold">Personal access token</h2>
            </div>
            {mode === "live" && hasToken ? (
              <span className="rounded border border-ok/30 bg-ok/5 px-2 py-0.5 text-[0.72rem] font-medium text-ok">
                active
              </span>
            ) : null}
          </div>

          <p id="token-description" className="mt-3 text-sm leading-relaxed text-muted">
            An operator creates a read-only token and places it in the server environment. The
            application never writes it to SQLite or returns it to the browser.
          </p>

          <div className="my-5 border-y border-rule bg-paper/60 px-3 py-3">
            <div className="eyebrow mb-2">Authorization path</div>
            <div className="flex flex-wrap items-center gap-2 font-mono text-[0.78rem] text-ink">
              <span>environment</span>
              <span className="text-accent" aria-hidden="true">→</span>
              <span>scanner</span>
              <span className="text-accent" aria-hidden="true">→</span>
              <span>DigitalOcean API</span>
            </div>
          </div>

          <dl className="grid grid-cols-2 gap-3 text-[0.8rem]">
            <div>
              <dt className="eyebrow">Required scope</dt>
              <dd className="mt-1 font-mono">api:read</dd>
            </div>
            <div>
              <dt className="eyebrow">Token lifecycle</dt>
              <dd className="mt-1">Until revoked</dd>
            </div>
          </dl>

          <span className="mt-auto pt-5 text-sm font-medium text-accent group-hover:underline">
            Use a personal access token →
          </span>
        </Link>
      </div>

      <section className="border-l-2 border-accent pl-4">
        <div className="eyebrow">Current connection</div>
        <p className="mt-1 text-sm text-muted">
          {account ? (
            <>
              <span className="font-medium text-ink">{account.name}</span> is selected from the
              most recently synced account using {mode === "live" ? "the live API" : "sample data"}.
            </>
          ) : (
            "No account has been synced yet."
          )}
        </p>

        {account && (
          <Link
            href="/"
            className="mt-3 inline-block text-sm font-medium text-accent hover:underline"
          >
            Open the assistant →
          </Link>
        )}
      </section>
    </div>
  );
}
