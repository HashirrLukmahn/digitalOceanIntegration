import { runAgent } from "./src/agent/run";
import { getAccount } from "./src/data/queries";

const account = getAccount();
console.log("account:", account?.name);
const r = await runAgent({ accountId: account!.id });
console.log("outcome :", r.outcome);
console.log("steps   :", r.steps);
console.log("error   :", r.error ?? "none");
console.log("findings:", r.findings.length);
for (const f of r.findings) {
  console.log("");
  console.log(`  [${f.severity}] ${f.title}`);
  console.log(`   chain    : ${f.resourceExternalIds.join("  ->  ")}`);
  console.log(`   builds on: ${f.supportingFindingKinds.join(", ") || "(none)"}`);
  console.log(`   reasoning: ${f.reasoning}`);
}
