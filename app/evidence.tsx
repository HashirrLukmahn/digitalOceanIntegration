/**
 * Evidence rendering.
 *
 * This is the part of the interface the product exists for. A finding is a claim,
 * and a claim in a security tool is worth exactly as much as the proof attached to
 * it, so the proof is rendered as an exhibit: provider values verbatim in monospace,
 * with the provenance of the conclusion stated first.
 *
 * Every rule already emits a provenance field -- `determinedBy` for configuration
 * inferences, `method` for demonstrated ones. Surfacing it means the reader never
 * has to take "this is public" on trust.
 */

function Provenance({ evidence }: { evidence: Record<string, unknown> }) {
  const determined = evidence.determinedBy ?? evidence.method;
  if (typeof determined !== "string") return null;

  const demonstrated = typeof evidence.method === "string";

  return (
    <div className="mb-3">
      <div className="eyebrow mb-1">
        {demonstrated ? "Determined by demonstration" : "Determined by configuration"}
      </div>
      <p className="font-mono text-[0.78rem] text-ink">{determined}</p>
    </div>
  );
}

const CONFIDENCE_LABEL: Record<string, string> = {
  provider_reported: "Provider-reported",
  derived: "Derived",
  active_probe: "Active probe",
  heuristic: "Heuristic",
};

/**
 * Why the finding has the severity it does, and how strongly the evidence supports it.
 *
 * Severity is impact; confidence is proof. Showing the derivation makes the number
 * auditable -- a reviewer sees `datastore × sensitive-port reachability ⇒ critical`
 * rather than being asked to trust a label -- and the confidence chip keeps a high-impact
 * heuristic from being mistaken for a verified exposure.
 */
function SeverityRationale({ evidence }: { evidence: Record<string, unknown> }) {
  const rationale = evidence.severityRationale as { formula?: unknown } | undefined;
  const formula = rationale && typeof rationale.formula === "string" ? rationale.formula : null;
  const confidence = typeof evidence.confidence === "string" ? evidence.confidence : null;
  if (!formula && !confidence) return null;

  return (
    <div className="mb-3">
      <div className="eyebrow mb-1">Severity rationale</div>
      {formula && <p className="font-mono text-[0.78rem] text-ink">{formula}</p>}
      {confidence && (
        <span className="mt-1.5 inline-block rounded border border-rule px-1.5 py-0.5 text-[0.7rem] text-faint">
          Confidence: {CONFIDENCE_LABEL[confidence] ?? confidence}
        </span>
      )}
    </div>
  );
}

/**
 * Where the data came from.
 *
 * The companion to confidence: the exact DigitalOcean API calls whose responses the finding
 * was derived from, plus the docs the rule cites. It lets a reader reproduce the evidence
 * rather than trust the provenance label.
 */
function DataSources({
  sources,
  references,
}: {
  sources?: readonly string[];
  references?: readonly string[];
}) {
  if ((!sources || sources.length === 0) && (!references || references.length === 0)) return null;

  return (
    <div className="mb-3">
      <div className="eyebrow mb-1">Sources</div>
      {sources && sources.length > 0 && (
        <ul className="space-y-0.5">
          {sources.map((call) => (
            <li key={call} className="font-mono text-[0.74rem] text-ink">
              {call}
            </li>
          ))}
        </ul>
      )}
      {references && references.length > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
          {references.map((url) => (
            <a
              key={url}
              href={url}
              target="_blank"
              rel="noreferrer"
              className="text-[0.74rem] text-accent hover:underline"
            >
              docs ↗
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex gap-3 py-1">
      <span className="w-44 flex-none text-[0.78rem] text-faint">{label}</span>
      <span className="font-mono text-[0.78rem] text-ink break-all">{value}</span>
    </div>
  );
}

/** Firewall rules that admit the internet, one line each. */
function OpenRules({ rules }: { rules: Array<Record<string, unknown>> }) {
  return (
    <div>
      <div className="eyebrow mb-1.5">Rules admitting the internet</div>
      <div className="exhibit space-y-1">
        {rules.map((rule, index) => (
          <div key={index} className="flex flex-wrap gap-x-3">
            <span className="text-critical">{String(rule.source)}</span>
            <span className="text-ink">→</span>
            <span className="text-ink">{String(rule.portsMeaning ?? rule.ports)}</span>
            <span className="text-faint">
              via {String(rule.firewallName)} ({String(rule.firewallId)})
            </span>
            {Array.isArray(rule.sensitiveServices) && rule.sensitiveServices.length > 0 && (
              <span className="text-high">
                {(rule.sensitiveServices as Array<{ service: string }>)
                  .map((s) => s.service)
                  .join(", ")}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

/** Plaintext credential-shaped variables: names only, never values. */
function Variables({ variables }: { variables: Array<Record<string, unknown>> }) {
  return (
    <div>
      <div className="eyebrow mb-1.5">Variables ({variables.length})</div>
      <div className="exhibit space-y-1">
        {variables.map((variable, index) => (
          <div key={index} className="flex flex-wrap gap-x-3">
            <span className="text-ink">{String(variable.key)}</span>
            <span className="text-faint">{String(variable.component)}</span>
            <span className="text-medium">looks like a {String(variable.looksLike)}</span>
          </div>
        ))}
      </div>
      <p className="mt-1.5 text-[0.78rem] text-faint">
        Detected by name and type. Values were not read.
      </p>
    </div>
  );
}

const LABELS: Record<string, string> = {
  publicAddresses: "Public addresses",
  publicAddress: "Public address",
  publicHost: "Public host",
  publicPort: "Public port",
  endpoint: "Endpoint",
  network: "Network",
  entryPorts: "Entry ports",
  sensitiveEntryPorts: "Sensitive entry ports",
  backendDropletIds: "Backend droplets",
  engine: "Engine",
  version: "Version",
  trustedSourceCount: "Trusted sources",
  attachedFirewallCount: "Attached firewalls",
  dropletTags: "Droplet tags",
  checkedAttachmentMethods: "Attachment checks performed",
  controlPlaneFirewallEnabled: "Control-plane firewall",
  allowedAddresses: "Allowed addresses",
  publicAllowlistEntry: "Allowlist entry",
  liveUrl: "Live URL",
  defaultIngress: "Default ingress",
  httpStatus: "HTTP status",
  region: "Region",
  reachability: "Reachability",
  redirectHttpToHttps: "Redirects HTTP to HTTPS",
  hasPrivateEndpoint: "Private endpoint available",
  privateNetworkUuid: "Private network",
};

const HANDLED = new Set([
  "confidence",
  "severityRationale",
  "determinedBy",
  "method",
  "note",
  "openRules",
  "variables",
  "valuesInspected",
  "publiclyListable",
  "forwardingRules",
  "publicTrustedSources",
  "otherTrustedSources",
  "attachedDatabases",
]);

function renderValue(value: unknown): React.ReactNode {
  if (value === null || value === undefined) return <span className="text-faint">—</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-faint">none</span>;
    return value.map((entry) => (typeof entry === "object" ? JSON.stringify(entry) : String(entry))).join(", ");
  }
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function Evidence({
  evidence,
  sources,
  references,
}: {
  evidence: Record<string, unknown>;
  sources?: readonly string[];
  references?: readonly string[];
}) {
  const openRules = Array.isArray(evidence.openRules)
    ? (evidence.openRules as Array<Record<string, unknown>>)
    : null;
  const variables = Array.isArray(evidence.variables)
    ? (evidence.variables as Array<Record<string, unknown>>)
    : null;
  const trusted = Array.isArray(evidence.publicTrustedSources)
    ? (evidence.publicTrustedSources as Array<Record<string, unknown>>)
    : null;

  const scalars = Object.entries(evidence).filter(([key]) => !HANDLED.has(key));

  return (
    <div className="space-y-4">
      <Provenance evidence={evidence} />
      <SeverityRationale evidence={evidence} />
      <DataSources sources={sources} references={references} />

      {openRules && openRules.length > 0 && <OpenRules rules={openRules} />}
      {variables && variables.length > 0 && <Variables variables={variables} />}

      {trusted && trusted.length > 0 && (
        <div>
          <div className="eyebrow mb-1.5">Trusted sources admitting the internet</div>
          <div className="exhibit space-y-1">
            {trusted.map((source, index) => (
              <div key={index}>
                <span className="text-faint">{String(source.type)}</span>{" "}
                <span className="text-critical">{String(source.value)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {scalars.length > 0 && (
        <div>
          <div className="eyebrow mb-1.5">Provider values</div>
          <div className="panel px-3 py-2">
            {scalars.map(([key, value]) => (
              <Row key={key} label={LABELS[key] ?? key} value={renderValue(value)} />
            ))}
          </div>
        </div>
      )}

      {typeof evidence.note === "string" && (
        <p className="text-[0.78rem] text-faint">{evidence.note}</p>
      )}
    </div>
  );
}
