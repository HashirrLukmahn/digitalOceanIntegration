# Adding a rule

The engine is a flat list of small, pure rules. Adding one is three steps: write the
rule, register it, test it. No framework, no base class, no wiring beyond one array entry.

A **base rule** looks at one resource family. A **path rule** runs in a second phase and
can read the relationship graph plus what phase one already found — that is where
cross-resource ("exploit through a public resource") findings live.

## 1. Write the rule

Create `src/exposure/rules/<name>.ts`. Copy this template and fill it in:

```typescript
import { externalId } from "../../normalize/resource";
import { deriveSeverity, severityEvidence } from "../severity";
import type { DraftFinding, ExposureRule } from "../types";

export const myRule: ExposureRule = {
  kind: "family.what_is_wrong",              // unique, dotted; also the finding's kind
  requires: ["<collector>"],                 // collectors this rule needs; skipped if they failed
  references: ["https://docs.digitalocean.com/..."], // >=1 DO doc URL (a test enforces this)
  // category: "attack_path",                // optional; set on cross-resource rules

  evaluate({ inventory /*, firewallsByDropletId, now */ }) {
    const findings: DraftFinding[] = [];

    for (const thing of inventory.things) {
      if (/* not actually a problem */) continue;      // fire only on a real, defensible issue

      const derivation = deriveSeverity("none", "web_ports"); // sensitivity x reachability

      findings.push({
        resourceExternalId: externalId("thing", thing.id),
        kind: "family.what_is_wrong",
        severity: derivation.final,          // or a fixed "low"|"medium"|"high"|"critical"
        confidence: "provider_reported",     // provider_reported | derived | active_probe | heuristic
        provesInternetExposure: false,       // true ONLY if this proves internet reachability
        title: "One line naming the problem",
        summary: "What is exposed and why it matters, in plain language.",
        evidence: {
          ...severityEvidence("provider_reported", derivation), // omit if severity is fixed
          // ...the exact provider values that prove the finding
        },
        remediation: "The specific corrective action.",
        stableElement: "what-must-change",   // the config element; keeps the fingerprint stable
        coverageKeys: ["<collector>"],        // datasets this finding depended on (reconciliation)
      });
    }

    return findings;
  },
};
```

A **path rule** is identical but implements `PathRule` and reads `relationships`,
`exposedResourceIds`, and `findingsByResource` from its context — see
`src/exposure/rules/path.ts` for two worked examples (a network-trust path and a
credential-leak path).

## 2. Register it

Add one line to `src/exposure/engine.ts`: import the rule and put it in `RULES` (or
`PATH_RULES` for a path rule). That is the whole registration.

## 3. Test it

Add cases to `tests/exposure.test.ts`. Every rule needs at least a **fires** case and a
**does-not-fire** case — the second is what proves it will not cry wolf. For a path rule,
drive it through `evaluateExposure(...)` so the two phases and the graph are exercised
together.

## The invariants (why the fields exist)

- **`requires` / `coverageKeys`** — a rule is *skipped* when its collectors failed (so an
  empty firewall list is never read as "no firewall"), and a finding is only *resolved*
  when every dataset it read was collected again. Set both to the collectors you actually
  read.
- **`confidence` is orthogonal to `severity`.** Severity is impact (sensitivity ×
  reachability); confidence is proof. A high-impact `heuristic` is shown as high-impact
  *and* heuristic — never silently downgraded, never dressed up as verified.
- **`provesInternetExposure`** is `true` only for a finding that proves the resource is
  reachable from the internet. A configuration or path finding sets it `false`.
- **`stableElement`** is the configuration element that must change. It makes the SHA-256
  fingerprint stable across syncs, so `first_seen_at` means something and a fix *resolves*
  a finding rather than mutating it. Sort any list you build it from.
- **Fire only on a defensible problem.** The guiding rule is "a missing finding beats an
  unsupported claim." Distinguish *unknown* (a collector did not run) from *absent* (the
  provider says the thing is not there) — never guess in the gap.

## What "more intricate" looks like

Single-resource rules are the floor. The interesting findings combine facts: a public
workload a datastore *trusts*, a public app that holds a datastore's credential in
plaintext, a public load balancer forwarding to a sensitive backend port the backend
firewall admits. Those are path rules, and they are where the engine earns its keep —
because each individual piece looks correctly configured and only the *combination* is the
breach. See `RISK-BACKLOG.md` for the next ones.
