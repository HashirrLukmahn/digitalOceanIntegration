import { Chat } from "./chat";
import { Empty } from "./components";
import { getAccount, getLatestRun } from "../src/data/queries";
import { agentApiKey } from "../src/agent/model";

export const dynamic = "force-dynamic";

export default function Home() {
  const account = getAccount();
  if (!account) {
    return (
      <Empty
        title="Nothing has been synced yet"
        hint="Connect a DigitalOcean account and run a sync — the assistant reads the stored snapshot."
      />
    );
  }

  const run = getLatestRun(account.id);
  const noKey = !agentApiKey();

  return (
    <>
      {noKey && (
        <div className="panel mx-auto mb-4 max-w-3xl border-dashed px-4 py-3 text-sm text-muted">
          <span className="font-medium text-ink">Assistant unavailable.</span> Set{" "}
          <span className="font-mono">ANTHROPIC_API_KEY</span> in{" "}
          <span className="font-mono">.env</span> and restart. The scanner and its rules work
          without it — only this page needs a key.
        </div>
      )}
      {run?.status === "partial" && (
        <p className="mx-auto mb-4 max-w-3xl text-[0.78rem] text-faint">
          Answers reflect the last sync, which was partial. Check coverage on the exposures page
          for what was not assessed.
        </p>
      )}
      <Chat />
    </>
  );
}
