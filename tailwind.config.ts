import type { Config } from "tailwindcss";

/**
 * Palette and scale are defined here once and referenced everywhere.
 *
 * The severity ramp deliberately ends in grey rather than green or yellow: a
 * `low` finding in this product means "public, and that is probably intentional"
 * -- a fact worth recording, not a warning. Colouring it like a caution would
 * undo the calibration the rule engine works hard to get right.
 */
export default {
  content: ["./app/**/*.{ts,tsx}", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        paper: "#F2F4F7",
        surface: "#FFFFFF",
        ink: "#10151C",
        muted: "#5A6675",
        faint: "#8A94A2",
        rule: "#DCE1E8",
        accent: "#0B5FFF",
        critical: "#A31515",
        high: "#C2410C",
        medium: "#B45309",
        low: "#5A6675",
        ok: "#0F766E",
      },
      fontFamily: {
        sans: ["var(--font-plex-sans)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-plex-mono)", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        micro: ["0.6875rem", { lineHeight: "1rem", letterSpacing: "0.06em" }],
      },
      borderRadius: { sm: "3px", DEFAULT: "3px", md: "4px" },
    },
  },
  plugins: [],
} satisfies Config;
