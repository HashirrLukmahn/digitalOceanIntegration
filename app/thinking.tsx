/**
 * What the assistant shows while it is working.
 *
 * The label changes with what is actually happening — reading resources, following
 * relationships, re-syncing — because "Thinking…" for eight seconds reads as a hang,
 * while naming the step reads as progress.
 */
export function Thinking({ label = "Thinking" }: { label?: string }) {
  return (
    <div className="space-y-2.5" role="status" aria-live="polite">
      <p className="text-[0.8rem] text-faint">
        {label}
        <span className="dots ml-0.5" aria-hidden="true">
          <span>.</span>
          <span>.</span>
          <span>.</span>
        </span>
      </p>
      <div className="space-y-1.5" aria-hidden="true">
        <div className="shimmer h-3 w-full" />
        <div className="shimmer h-3 w-[88%]" />
        <div className="shimmer h-3 w-[64%]" />
      </div>
    </div>
  );
}
