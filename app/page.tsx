import { Chat } from "./chat";
import { agentApiKey } from "../src/agent/model";
import { getAccount, getLatestRun } from "../src/data/queries";
import { requireConnection } from "../src/connection/state";

export const dynamic = "force-dynamic";

/**
 * The assistant, gated on there being something to talk about.
 *
 * A conversation with no snapshot behind it is worse than no conversation: every
 * answer would be "no resources found", which reads as "your account is clean"
 * rather than "nothing has been scanned". So an unverified connection is sent to
 * /connections instead, where the state is explained and fixable.
 *
 * The gate is a server-side redirect rather than middleware because it depends on a
 * SQLite read, and middleware runs before that is available.
 */
export default function Home() {
  requireConnection();
  const account = getAccount()!;
  const run = getLatestRun(account.id)!;

  return (
    <>
      {!agentApiKey() && (
        <div className="panel mx-auto mb-4 max-w-3xl border-dashed px-4 py-3 text-sm text-muted">
          <span className="font-medium text-ink">Assistant unavailable.</span> Set{" "}
          <span className="font-mono">ANTHROPIC_API_KEY</span> or{" "}
          <span className="font-mono">AI_API_KEY</span> in{" "}
          <span className="font-mono">.env</span> and restart. The scanner and its rules work
          without it — only this page needs a key.
        </div>
      )}
      {run.status === "partial" && (
        <p className="mx-auto mb-4 max-w-3xl text-[0.78rem] text-faint">
          Answers reflect the last sync, which was partial. Check coverage on the exposures page
          for what was not assessed.
        </p>
      )}
      <Chat />
    </>
  );
}
