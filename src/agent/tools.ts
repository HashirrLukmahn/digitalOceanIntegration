import { tool, type Tool } from "ai";
import { z } from "zod";
import { getResourceEdges, listFindings, listResources } from "../data/queries";
import { catalogueEntry } from "../exposure/catalogue";
import { apiCallsForFinding, referencesForFinding } from "../exposure/sources";
import { createTransport } from "../do/transport";
import { runSync } from "../sync/run";

/** How severity and confidence work, stated once for the explain_rule tool. */
const SEVERITY_MODEL =
  "Severity = sensitivity (what the resource holds: datastore > credential > none) × " +
  "reachability/accessibility (how much the internet can reach it: sensitive ports > all ports > " +
  "web ports > restricted), read from a fixed matrix and then shifted by bounded, named modifiers. " +
  "Confidence (provider_reported, derived, active_probe, heuristic) is a separate axis -- it says how " +
  "strong the proof is and never changes the severity level.";

/**
 * The agent's tools.
 *
 * The query tools read the stored snapshot and nothing else. None can write, and none
 * can reach DigitalOcean — which is what makes a run reproducible against the data it
 * saw, and what makes a droplet named `"ignore previous instructions"` a bad finding
 * rather than a live API call.
 *
 * `refresh_snapshot` is the one exception and is opt-in. The conversational assistant
 * gets it, because "my data is stale" is a reasonable thing to ask it to fix. The
 * batch agent does not, because analysing a point-in-time snapshot is the entire basis
 * of its reproducibility — re-syncing halfway through would mean its findings referred
 * to data that no longer existed when it started.
 *
 * Each query tool is a thin projection over a function the UI already uses.
 */

export const SEVERITY = z.enum(["low", "medium", "high", "critical"]);

export interface ToolOptions {
  /** Give the agent the ability to re-sync from DigitalOcean. Off by default. */
  allowRefresh?: boolean;
}

export function buildTools(
  accountId: string,
  options: ToolOptions = {},
): Record<string, Tool> {
  const tools: Record<string, Tool> = {
    query_resources: tool({
      description:
        "List synced resources. Omit all filters to see the whole account. Returns " +
        "external ids, type, region, whether the resource is internet-facing, its " +
        "sensitivity, and allowlisted provider metadata.",
      inputSchema: z.object({
        resourceType: z
          .string()
          .optional()
          .describe('e.g. "digitalocean.droplet", "digitalocean.database_cluster"'),
        region: z.string().optional(),
        exposure: z.enum(["exposed", "not_exposed"]).optional(),
        sensitivity: z.enum(["none", "credential", "datastore"]).optional(),
      }),
      execute: async ({ resourceType, ...rest }) =>
        listResources(accountId, { type: resourceType, ...rest }).map((r) => ({
          externalId: r.externalId,
          resourceType: r.resourceType,
          name: r.name,
          region: r.region,
          isInternetExposed: r.isInternetExposed,
          sensitivity: r.sensitivity,
          tags: r.tagsJson,
          metadata: r.metadataJson,
        })),
    }),

    query_rule_findings: tool({
      description:
        "List findings already produced by the deterministic rule engine. These are the " +
        "confirmed single-resource problems and the usual starting points for a chain -- do " +
        "not re-report them. Each finding tells you the rule it violated (`kind` + " +
        "`ruleExplanation`), WHY it has its severity and accessibility (`severityReasoning`), " +
        "how strong the proof is (`confidence`), the exact DigitalOcean API calls behind it " +
        "(`sources`), the documentation it cites (`references`), and the fix (`remediation`).",
      inputSchema: z.object({
        severity: SEVERITY.optional(),
        kind: z.string().optional().describe('e.g. "droplet.public_ingress"'),
      }),
      execute: async (filters) =>
        listFindings(accountId, filters).map((f) => {
          const evidence = f.evidenceJson as Record<string, unknown>;
          const rationale = evidence.severityRationale as { formula?: unknown } | undefined;
          return {
            resourceExternalId: f.resourceExternalId,
            kind: f.kind,
            ruleExplanation: catalogueEntry(f.kind)?.title ?? null,
            severity: f.severity,
            severityReasoning:
              rationale && typeof rationale.formula === "string" ? rationale.formula : null,
            confidence: typeof evidence.confidence === "string" ? evidence.confidence : null,
            sources: apiCallsForFinding(f.kind, f.coverageKeysJson),
            references: referencesForFinding(f.kind),
            coverageKeys: f.coverageKeysJson,
            remediation: f.remediation,
            evidence: f.evidenceJson,
          };
        }),
    }),

    explain_rule: tool({
      description:
        "Explain one rule/finding kind: what it flags, why it carries the severity it does, " +
        "which DigitalOcean API calls it reads, and the documentation it cites. Use it to " +
        "justify a finding's rule, its severity, and its accessibility in your own words.",
      inputSchema: z.object({
        kind: z
          .string()
          .describe('The rule/finding kind, e.g. "database.trusted_source_is_public"'),
      }),
      execute: async ({ kind }) => {
        const entry = catalogueEntry(kind);
        return {
          kind,
          flags: entry?.title ?? "Unknown rule kind.",
          group: entry?.group ?? null,
          dataSources: apiCallsForFinding(kind, []),
          references: referencesForFinding(kind),
          severityModel: SEVERITY_MODEL,
        };
      },
    }),

    query_relationships: tool({
      description:
        "Edges into and out of one resource: what contains it, what is attached to " +
        "it, what routes to it, what depends on it. This is how you traverse from an " +
        "entry point to a target.",
      inputSchema: z.object({
        externalId: z.string().describe('e.g. "do:droplet:101"'),
      }),
      execute: async ({ externalId }) => {
        const { outgoing, incoming } = getResourceEdges(accountId, externalId);
        const shape = (e: (typeof outgoing)[number]) => ({
          source: e.sourceExternalId,
          target: e.targetExternalId,
          relationship: e.relationship,
          evidence: e.evidence,
          metadata: e.metadataJson,
        });
        return { outgoing: outgoing.map(shape), incoming: incoming.map(shape) };
      },
    }),

  };

  if (options.allowRefresh) {
    /**
     * The one tool that reaches DigitalOcean.
     *
     * Read-only — a sync lists resources, it never mutates anything — but it is still
     * the exception to "this agent only reads a stored snapshot", so it is worth being
     * deliberate about. It takes seconds rather than milliseconds and it changes the
     * data underneath the conversation, so the description tells the model to use it
     * only when staleness is actually the problem.
     */
    tools.refresh_snapshot = tool({
      description:
        "Re-read the account from DigitalOcean and update the stored snapshot. Slow " +
        "(several seconds) and only useful if the data is stale or the user says they " +
        "changed something. Do not call it speculatively, and never more than once.",
      inputSchema: z.object({
        reason: z.string().describe("Why a refresh is needed, in a few words"),
      }),
      execute: async ({ reason }) => {
        const result = await runSync({ http: createTransport() });
        return {
          reason,
          status: result.status,
          resources: result.resourcesCount,
          findings: result.findingsCount,
          note:
            result.status === "partial"
              ? "Partial sync — some collectors did not run. Check coverage before " +
                "concluding anything is absent."
              : "Snapshot updated. Re-query to see the new data.",
        };
      },
    });
  }

  /**
     * Terminal. The loop stops on the *call*, so the return value is never read by the
     * model — it exists so the SDK has something to record.
     */
  tools.report_findings = tool({
      description:
        "Report your conclusions and finish. An empty array is a valid, complete " +
        "result and is the correct answer for most accounts. Call this exactly once.",
      inputSchema: z.object({
        findings: z
          .array(
            z.object({
              title: z.string().describe("One line, naming the path"),
              severity: SEVERITY,
              hops: z
                .array(
                  z.object({
                    resourceExternalId: z
                      .string()
                      .describe('The resource reached at this step, e.g. "do:droplet:101"'),
                    viaRelationship: z
                      .enum(["contains", "attached_to", "routes_to", "depends_on", "trusts"])
                      .optional()
                      .describe(
                        "The edge you followed to reach this resource, from query_relationships. " +
                          "Omit on the first (entry) hop only.",
                      ),
                    viaDirection: z
                      .enum(["outbound", "inbound"])
                      .optional()
                      .describe(
                        "outbound = you followed the edge from its source to its target; " +
                          "inbound = from its target back to its source. Omit on the entry hop.",
                      ),
                    findingKind: z
                      .string()
                      .optional()
                      .describe('A rule finding at this resource, by kind, if any (e.g. "droplet.public_ingress")'),
                  }),
                )
                .min(2)
                .describe(
                  "The ordered path, entry first. Two or more hops, or it is not a chain. " +
                    "Every hop after the first must name the edge that reached it.",
                ),
              reasoning: z
                .string()
                .describe("How an attacker gets from the entry point to the target"),
              remediation: z
                .string()
                .describe("A concrete fix that breaks the path -- required, not optional"),
            }),
          )
          .describe("Empty array if no multi-resource path exists."),
      }),
    execute: async (input) => input,
  });

  return tools;
}

/**
 * Returns the prior result for a repeated identical call.
 *
 * Without this, a model that is unsure what to do next re-issues the same query and
 * burns the step budget discovering the same data. The note tells it the repeat was
 * noticed, which is what actually breaks the loop.
 */
export function withRepeatGuard(tools: Record<string, Tool>): Record<string, Tool> {
  const seen = new Map<string, unknown>();

  return Object.fromEntries(
    Object.entries(tools).map(([name, definition]) => [
      name,
      {
        ...definition,
        execute: async (args: unknown, options: unknown) => {
          const key = `${name}:${JSON.stringify(args)}`;
          if (seen.has(key)) {
            return {
              note:
                "You already made this exact call. Returning the previous result " +
                "unchanged. Try different arguments, or call report_findings to finish.",
              result: seen.get(key),
            };
          }
          const result = await (
            definition.execute as (a: unknown, o: unknown) => Promise<unknown>
          )(args, options);
          seen.set(key, result);
          return result;
        },
      } as Tool,
    ]),
  );
}
