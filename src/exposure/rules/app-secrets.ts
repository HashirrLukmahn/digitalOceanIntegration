import { externalId } from "../../normalize/resource";
import type { DoApp, DoAppEnvVar } from "../../do/types";
import type { DraftFinding, ExposureRule } from "../types";

/**
 * App Platform variables that look like secrets but are stored in plaintext.
 *
 * App Platform variables carry a `type` of GENERAL or SECRET. SECRET values are
 * encrypted at rest by DigitalOcean; GENERAL values are not, and GENERAL is the
 * default. So a variable named `STRIPE_API_KEY` left at the default is returned in
 * plaintext by the ordinary `/v2/apps` listing, visible to anyone who can read the
 * app spec -- every team member with resource access, every CI job with a token,
 * and any tool the account is connected to. Including this one.
 *
 * The check is on the variable's NAME. The value is never read, never stored, and
 * never logged: a rule about mishandled secrets that copied the secret to make its
 * point would be self-defeating.
 *
 * This is a configuration finding rather than a reachability one, so it sets
 * `provesInternetExposure: false` and does not mark the app internet-exposed.
 */

/**
 * Name fragments that indicate credential material.
 *
 * Kept conservative. `KEY` alone is not here, because `SORT_KEY`, `PARTITION_KEY`
 * and `IDEMPOTENCY_KEY` are ordinary configuration, and a rule that cries wolf on
 * those trains people to ignore it.
 */
const SECRET_NAME_PATTERNS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  { pattern: /(^|_)API_?KEY($|_)/i, label: "API key" },
  { pattern: /(^|_)SECRET($|_)|_SECRET$/i, label: "secret" },
  { pattern: /(^|_)PASSWORD($|_)|_PASSWD$/i, label: "password" },
  { pattern: /(^|_)TOKEN($|_)|_TOKEN$/i, label: "token" },
  { pattern: /(^|_)PRIVATE_?KEY($|_)/i, label: "private key" },
  { pattern: /(^|_)ACCESS_?KEY($|_)/i, label: "access key" },
  { pattern: /(^|_)CREDENTIALS?($|_)/i, label: "credentials" },
  { pattern: /(^|_)(DATABASE|DB|REDIS|MONGO|AMQP)_?URL($|_)/i, label: "connection URL" },
  { pattern: /(^|_)DSN($|_)/i, label: "data source name" },
  { pattern: /(^|_)AUTH($|_)/i, label: "auth material" },
];

function classify(key: string): string | null {
  for (const { pattern, label } of SECRET_NAME_PATTERNS) {
    if (pattern.test(key)) return label;
  }
  return null;
}

/** App-level variables plus every component's, tagged with where they came from. */
function allVariables(app: DoApp): Array<{ component: string; variable: DoAppEnvVar }> {
  const spec = app.spec;
  if (!spec) return [];

  const out: Array<{ component: string; variable: DoAppEnvVar }> = [];
  for (const variable of spec.envs ?? []) out.push({ component: "app", variable });

  const componentGroups: Array<[string, typeof spec.services]> = [
    ["service", spec.services],
    ["worker", spec.workers],
    ["job", spec.jobs],
    ["function", spec.functions],
    ["static_site", spec.static_sites],
  ];

  for (const [kind, components] of componentGroups) {
    for (const component of components ?? []) {
      for (const variable of component.envs ?? []) {
        out.push({ component: `${kind}:${component.name ?? "unnamed"}`, variable });
      }
    }
  }

  return out;
}

export const appPlaintextSecretEnvRule: ExposureRule = {
  kind: "app.plaintext_secret_env",
  evaluate({ inventory }) {
    const findings: DraftFinding[] = [];

    for (const app of inventory.apps) {
      const offenders: Array<{ key: string; component: string; scope: string; looksLike: string }> =
        [];

      for (const { component, variable } of allVariables(app)) {
        const key = variable.key;
        if (!key) continue;

        // GENERAL is the default, so an absent type is plaintext too.
        const isPlaintext = (variable.type ?? "GENERAL") !== "SECRET";
        if (!isPlaintext) continue;

        const looksLike = classify(key);
        if (!looksLike) continue;

        offenders.push({
          key,
          component,
          scope: variable.scope ?? "RUN_AND_BUILD_TIME",
          looksLike,
        });
      }

      if (offenders.length === 0) continue;

      const name = app.spec?.name ?? app.id;

      findings.push({
        resourceExternalId: externalId("app", app.id),
        kind: "app.plaintext_secret_env",
        // Not internet reachability, so severity reflects disclosure risk to anyone
        // with read access to the account rather than to the whole internet. The
        // GENERAL type is a value DigitalOcean returns, so confidence is provider_reported.
        severity: "medium",
        confidence: "provider_reported",
        title: `App stores ${offenders.length} credential-like variable(s) in plaintext`,
        summary:
          `App "${name}" defines ${offenders.length} environment variable(s) whose names ` +
          `indicate credential material (${offenders.map((o) => o.key).join(", ")}) with type ` +
          `GENERAL rather than SECRET. GENERAL variables are stored unencrypted and are ` +
          `returned in plaintext by the apps API, so anyone who can read this app's spec can ` +
          `read the value.`,
        evidence: {
          // A disclosure finding rather than a reachability one, so severity is a fixed
          // level with an explicit rationale rather than a sensitivity × reachability draw.
          confidence: "provider_reported",
          severityRationale: {
            base: "medium",
            modifiers: [],
            final: "medium",
            formula: "credential disclosure to anyone with read access to the app spec ⇒ medium",
          },
          // Names and locations only. The values are deliberately never read.
          variables: offenders,
          valuesInspected: false,
          note: "Detection is by variable name and type. Values are never read, stored, or logged.",
        },
        remediation:
          "Change these variables to type SECRET in the app spec so DigitalOcean encrypts them, " +
          "then rotate the underlying credentials -- the plaintext values should be treated as " +
          "disclosed to everyone who has had read access to the app.",
        stableElement: offenders
          .map((o) => `${o.component}:${o.key}`)
          .sort()
          .join("|"),
        provesInternetExposure: false,
      });
    }

    return findings;
  },
};
