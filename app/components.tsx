import Link from "next/link";
import type { SyncCoverage } from "../src/db/schema";
import { dataSource, digitalOceanToken } from "../src/lib/env";

/**
 * Shared presentational pieces.
 *
 * Two of these carry the product's argument rather than merely rendering data:
 * `Severity` renders a fill level so the ramp survives without colour, and
 * `Coverage` states what was *not* assessed on every page that shows results.
 */

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

export function Severity({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center gap-2 ${SEVERITY_CLASS[level] ?? "text-low"}`}>
      <span className="sev" data-level={level} aria-hidden="true">
        <i />
        <i />
        <i />
        <i />
      </span>
      <span className="text-[0.8rem] font-medium capitalize">{level}</span>
    </span>
  );
}

export function Urn({ id, href }: { id: string; href?: string }) {
  if (href) {
    return (
      <Link href={href} className="urn hover:text-accent hover:underline">
        {id}
      </Link>
    );
  }
  return <span className="urn">{id}</span>;
}

export function Exposed({ value }: { value: boolean }) {
  return value ? (
    <span className="text-[0.8rem] font-medium text-critical">Internet-facing</span>
  ) : (
    <span className="text-[0.8rem] text-faint">Not reachable</span>
  );
}

export function Sensitivity({ value }: { value: string }) {
  if (value === "none") return <span className="text-[0.8rem] text-faint">—</span>;
  return (
    <span className="text-[0.8rem] text-ink">
      {value === "datastore" ? "Datastore" : "Credential"}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const tone =
    status === "completed"
      ? "text-ok border-ok/30 bg-ok/5"
      : status === "partial"
        ? "text-medium border-medium/30 bg-medium/5"
        : status === "failed"
          ? "text-critical border-critical/30 bg-critical/5"
          : "text-muted border-rule bg-paper";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-micro uppercase tracking-[0.08em] ${tone}`}>
      {status}
    </span>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="eyebrow mb-1">{label}</div>
      <div className="text-sm">{children}</div>
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint: string }) {
  return (
    <div className="panel p-8 text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 text-sm text-muted">{hint}</p>
    </div>
  );
}

/**
 * What this run could not see.
 *
 * Shown wherever results are shown. A scanner that reports only what it found
 * invites the reader to assume the rest was checked and was clean.
 */
export function Coverage({ coverage }: { coverage: SyncCoverage }) {
  const gaps = [
    ...(coverage.failedCollectors ?? []).map((c) => ({ ...c, kind: "failed" as const })),
    ...(coverage.unavailableCollectors ?? []).map((c) => ({ ...c, kind: "unavailable" as const })),
  ];

  const spaces = coverage.spaces ? (
    <p className="mt-2 text-[0.78rem] text-muted">
      Object storage: {coverage.spaces.bucketsAssessed} named bucket(s) assessed in{" "}
      <span className="font-mono">{coverage.spaces.mode}</span> mode. Account-wide bucket
      enumeration is not available to a read-only credential.
    </p>
  ) : null;

  if (gaps.length === 0) {
    return (
      <div className="panel px-4 py-3 text-sm">
        <span className="text-ok font-medium">Complete coverage.</span>{" "}
        <span className="text-muted">
          All {coverage.completedCollectors.length} collectors ran.
        </span>
        {spaces}
      </div>
    );
  }

  return (
    <div className="panel border-dashed px-4 py-3">
      <div className="eyebrow mb-2">Not assessed</div>
      <ul className="space-y-1.5">
        {gaps.map((gap) => (
          <li key={gap.collector} className="text-sm leading-snug">
            <span className="font-mono text-[0.78rem] text-ink">{gap.collector}</span>
            <span className="text-faint"> · {gap.kind}</span>
            <p className="text-muted mt-0.5">{gap.message}</p>
          </li>
        ))}
      </ul>
      {spaces}
      <p className="mt-3 text-[0.78rem] text-faint">
        Findings below describe only what was assessed. An absent finding is not evidence of a
        safe configuration for anything listed here.
      </p>
    </div>
  );
}

/**
 * States, on every page, when the numbers on screen are not from a real account.
 *
 * This sits above the navigation rather than on the connection page, because the
 * connection page is not where somebody forms a belief about their security posture
 * -- the findings list is. A security tool that displays fabricated findings without
 * saying so on the same screen is worse than one that displays nothing.
 */
export function ModeBanner() {
  const mode = dataSource();

  if (mode === "fixtures") {
    return (
      <div className="border-b border-dashed border-medium/50 bg-medium/5">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-baseline gap-x-3 gap-y-1 px-6 py-2">
          <span className="text-[0.8rem] font-semibold text-medium">Sample data</span>
          <span className="text-[0.8rem] text-muted">
            This is a built-in fixture account, not a real DigitalOcean team. Every resource and
            finding below is invented so the app can be evaluated without a token.
          </span>
          <span className="ml-auto text-[0.78rem] text-faint">
            Set <span className="font-mono">DATA_SOURCE=live</span> to scan a real account.
          </span>
        </div>
      </div>
    );
  }

  if (!digitalOceanToken()) {
    return (
      <div className="border-b border-dashed border-critical/50 bg-critical/5">
        <div className="mx-auto max-w-[1400px] px-6 py-2 text-[0.8rem] text-critical">
          No DigitalOcean token is configured. Set{" "}
          <span className="font-mono">DIGITALOCEAN_TOKEN</span> in{" "}
          <span className="font-mono">.env</span>, or use{" "}
          <span className="font-mono">DATA_SOURCE=fixtures</span> to explore with sample data.
        </div>
      </div>
    );
  }

  return null;
}

export function timeAgo(date: Date | null): string {
  if (!date) return "never";
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatTime(date: Date | null): string {
  return date ? date.toISOString().replace("T", " ").slice(0, 19) + "Z" : "—";
}
