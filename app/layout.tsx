import type { Metadata } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";
import "./globals.css";
import { getAccount, getLatestRun } from "../src/data/queries";
import { ModeBanner, timeAgo } from "./components";

/**
 * IBM Plex, deliberately: it was drawn for technical products, and using its sans
 * and mono together lets the interface distinguish our prose from the provider's
 * verbatim values without introducing a second typeface family.
 */
const sans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-sans",
  display: "swap",
});

const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "DigitalOcean exposure review",
  description: "Inventory a DigitalOcean team and identify internet-exposed resources.",
};

const NAV = [
  { href: "/exposures", label: "Exposures" },
  { href: "/inventory", label: "Inventory" },
  { href: "/syncs", label: "Syncs" },
  { href: "/connections", label: "Connection" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const account = getAccount();
  const run = account ? getLatestRun(account.id) : null;

  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="min-h-screen">
        <ModeBanner />
        <header className="border-b border-rule bg-surface">
          <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-8 gap-y-3 px-6 py-3">
            <Link href="/exposures" className="flex items-baseline gap-2.5">
              <span className="text-[0.95rem] font-semibold tracking-tight">Exposure review</span>
              <span className="eyebrow">DigitalOcean</span>
            </Link>

            <nav className="flex items-center gap-1" aria-label="Sections">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="rounded px-2.5 py-1 text-sm text-muted hover:bg-paper hover:text-ink"
                >
                  {item.label}
                </Link>
              ))}
            </nav>

            <div className="ml-auto flex items-center gap-5 text-[0.8rem]">
              {account ? (
                <>
                  <span className="text-ink">{account.name}</span>
                  <span className="text-faint">
                    synced {timeAgo(account.lastSyncedAt)}
                    {run ? ` · ${run.status}` : ""}
                  </span>
                </>
              ) : (
                <span className="text-faint">No account connected</span>
              )}
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-[1400px] px-6 py-8">{children}</main>

        <footer className="mx-auto max-w-[1400px] px-6 pb-10 text-[0.78rem] text-faint">
          Findings are produced by deterministic rules over a stored snapshot. Values shown in
          monospace are reproduced verbatim from the DigitalOcean API.
        </footer>
      </body>
    </html>
  );
}
