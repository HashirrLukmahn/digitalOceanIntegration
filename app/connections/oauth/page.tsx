import Link from "next/link";

export default function OAuthConnectionPage() {
  return (
    <div className="max-w-4xl space-y-6">
      <header className="max-w-2xl">
        <Link href="/connections" className="text-[0.8rem] text-accent hover:underline">
          ← Change connection method
        </Link>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <h1 className="text-lg font-semibold tracking-tight">OAuth connection</h1>
          <span className="unknown">setup required</span>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-muted">
          OAuth is the better fit for a shared deployment because each team approves access in
          DigitalOcean and can revoke it there. No authorization request is sent from this screen.
        </p>
      </header>

      <section className="panel overflow-hidden">
        <div className="border-b border-rule bg-paper/60 px-4 py-3">
          <div className="eyebrow">Authorization code flow</div>
          <div className="mt-2 flex flex-wrap items-center gap-2 font-mono text-[0.78rem]">
            <span>authorize</span>
            <span className="text-accent" aria-hidden="true">→</span>
            <span>callback</span>
            <span className="text-accent" aria-hidden="true">→</span>
            <span>token exchange</span>
            <span className="text-accent" aria-hidden="true">→</span>
            <span>read-only sync</span>
          </div>
        </div>

        <ol className="divide-y divide-rule">
          <li className="grid gap-2 px-4 py-4 sm:grid-cols-[2rem_1fr]">
            <span className="font-mono text-[0.78rem] text-faint">01</span>
            <div>
              <h2 className="text-sm font-semibold">Register the OAuth application</h2>
              <p className="mt-1 text-sm text-muted">
                DigitalOcean provides a client ID and client secret, tied to an exact callback URL.
              </p>
            </div>
          </li>
          <li className="grid gap-2 px-4 py-4 sm:grid-cols-[2rem_1fr]">
            <span className="font-mono text-[0.78rem] text-faint">02</span>
            <div>
              <h2 className="text-sm font-semibold">Request read-only authorization</h2>
              <p className="mt-1 text-sm text-muted">
                Redirect with <span className="font-mono">response_type=code</span>, scope{" "}
                <span className="font-mono">api:read</span>, and an unguessable state value.
              </p>
            </div>
          </li>
          <li className="grid gap-2 px-4 py-4 sm:grid-cols-[2rem_1fr]">
            <span className="font-mono text-[0.78rem] text-faint">03</span>
            <div>
              <h2 className="text-sm font-semibold">Exchange the callback code server-side</h2>
              <p className="mt-1 text-sm text-muted">
                Verify state first, then exchange the short-lived code without exposing the client
                secret or returned tokens to the browser.
              </p>
            </div>
          </li>
          <li className="grid gap-2 px-4 py-4 sm:grid-cols-[2rem_1fr]">
            <span className="font-mono text-[0.78rem] text-faint">04</span>
            <div>
              <h2 className="text-sm font-semibold">Protect refreshable credentials</h2>
              <p className="mt-1 text-sm text-muted">
                The access and single-use refresh tokens need encrypted storage, rotation, and a
                disconnect path before OAuth can safely power background syncs.
              </p>
            </div>
          </li>
        </ol>
      </section>

      <div className="flex flex-wrap items-center gap-3">
        <a
          href="https://docs.digitalocean.com/reference/api/oauth/"
          className="btn-primary"
          target="_blank"
          rel="noreferrer"
        >
          Open DigitalOcean OAuth docs
        </a>
        <Link href="/connections/api-token" className="btn-quiet">
          Use a personal access token now
        </Link>
      </div>
    </div>
  );
}
