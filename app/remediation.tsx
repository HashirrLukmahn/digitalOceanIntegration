import { remediationCommand } from "../src/exposure/remediation-command";

/**
 * The exact fix, where one exists.
 *
 * Rendered under the prose rather than replacing it: the prose explains what to
 * achieve, the command is one correct way to achieve it. Findings whose fix depends
 * on the operator's topology show prose only.
 */
export function RemediationBlock({
  kind,
  resourceExternalId,
  evidence,
}: {
  kind: string;
  resourceExternalId: string;
  evidence: Record<string, unknown>;
}) {
  const fix = remediationCommand(kind, resourceExternalId, evidence);
  if (!fix) return null;

  return (
    <div className="mt-3">
      <div className="eyebrow mb-1">Command</div>
      <p className="mb-1.5 text-[0.78rem] text-muted">{fix.effect}</p>
      <pre className="exhibit whitespace-pre-wrap">{fix.command}</pre>
    </div>
  );
}
