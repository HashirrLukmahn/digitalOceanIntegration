# Engine hardening plan

Response to the review feedback on the first working draft. This is a plan, not an
implementation — it states the problem, the DigitalOcean-specific risks worth detecting,
and the concrete additions to the spec, engine, collectors, and UI. Every new rule below
is grounded in the DigitalOcean docs or public OpenAPI and carries a citation, because
the whole point of this tool is that a finding survives a reviewer asking "prove it."

The existing design principles are load-bearing and are **not** up for renegotiation
here:

- **Deterministic rules decide; a model never does.** An LLM may explain or chain, but
  it cannot invent a finding (`digitalocean-cloud-inventory.md`, "Exposure rules").
- **Severity is calibrated, not maximal** — sensitivity × reachability
  (`src/exposure/severity.ts`). A public 443 is `low`; a database open to `0.0.0.0/0` is
  `critical`.
- **Evidence is provider-reported.** A missing finding beats an unsupported claim
  (`src/relationships/derive.ts` header).
- **Unknown never looks like safe.** Absence of a finding is not a clean bill
  (`DESIGN-NOTES.md`).

Everything proposed here is required to obey those four rules.

---

## Problem statement

The reviewer raised six items across two themes.

### Theme 1 — a more robust engine

- **(1a) Adding rules must be low-friction.** A contributor should be able to add a new
  detection by writing one file, not by threading state through five. Today a rule is
  already one file implementing `ExposureRule` (`src/exposure/types.ts`), but everything
  a rule can *see* is hard-wired into `ExposureContext` (`inventory` +
  `firewallsByDropletId`). A rule that needs "droplets by tag" or "certificates by load
  balancer" has nowhere to get it, so the next contributor either recomputes indices by
  hand or gives up. The friction is the shared context, not the file count.
- **(1b) Detect exploitation of other resources *through* a public one.** Cross-resource
  attack paths — an internet-exposed droplet that is a trusted source of a managed
  database — where each resource in isolation looks fine. An LLM pass for this already
  exists (`src/agent/run.ts`), but the *clean, provable* chains belong in the
  deterministic engine where they are reproducible and citeable.
- **(1c) The engine is too rudimentary.** Nine rules covering the obvious public-IP and
  open-port cases. DigitalOcean's access model is thinner than the hyperscalers' — it has
  no service accounts, and while it *does* provide [predefined and custom team
  roles](https://docs.digitalocean.com/platform/teams/roles/), role administration is not
  fully exposed through the API, so most of the AWS/Azure/GCP playbook (over-permissive
  roles, public S3 policies, key sprawl) either does not translate or cannot be assessed
  by API and becomes a manual attestation (see the addendum's manual-controls section).
  The risks that *are* API-detectable on DigitalOcean live in different places — DNS,
  certificates, engine end-of-life, egress, App Platform ingress, cross-resource trust —
  and the current engine sees none of them.

### Theme 2 — spec / product updates

- **(2a)** A per-snapshot "download JSON" button. Today export is global and current-state
  only (`app/api/export/route.ts`); there is no way to download the exact inventory a
  given historical sync produced.
- **(2d)** Visualize vulnerabilities and relationships, so risk is legible as a graph
  rather than only as tables.
- **(2e)** A harness that enforces citation of sources, blocks hallucination, and always
  recommends the required fix — for both the deterministic findings and the LLM pass.

---

## What DigitalOcean actually lets us detect

DigitalOcean is genuinely different from the hyperscalers, and the honest framing is that
some entire categories are **not** detectable with a read-only `api:read` token. Stating
those up front keeps the rest defensible.

**Confirmed blind spots (documented, not worked around):**

| Blind spot | Why | Source |
|---|---|---|
| API token sprawl / scopes / last-used | No `/v2/tokens` endpoint exists at all | `DESIGN-NOTES.md`, checked against all 445 spec paths |
| Team member roles ("who has admin") | `/v2/organizations/teams` returns only `member_count` | `DESIGN-NOTES.md` |
| Container registry made "public" | **DOCR is private-only — there is no public/anonymous-pull field.** The AWS/GCR "public registry" class does not exist here | `registry_base.yml` has only `name`/`region`/`created_at`/`storage_usage_bytes`; docs frame DOCR as "a private Docker image registry" |
| Managed DB "reachable without TLS" | TLS is enforced server-side; `connection.ssl` is a client hint, not a posture. `ssl=false` would be a false positive | [PostgreSQL secure](https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/), [MySQL secure](https://docs.digitalocean.com/products/databases/mysql/how-to/secure/) |
| Snapshot / image cross-account *transfer* | Sharing is a `POST … account_transfer` action, not readable state | `images` action API |
| SSH key age / rotation / last-used | `/v2/account/keys` returns only `id`/`fingerprint`/`public_key`/`name` | `sshKeys.yml` |
| Spaces bucket enumeration | v2 API cannot list buckets or read ACLs; needs the S3 API and a second credential | `DESIGN-NOTES.md` (already handled by the anonymous-probe design) |

These stay in the coverage report as "not assessed," never as "safe." Do not invent
fields to cover them.

---

## Part 1 — a more robust engine

### 1a. Rule contribution ergonomics (make adding a rule frictionless)

**Goal:** a new detection is *one file* that declares what data it needs and returns
findings, plus *one line* registering it. No contributor should touch the fingerprinting,
severity, persistence, or context-building code to add a rule.

**Design.** Keep the codebase's existing preference for explicit registration (mirrors
the `COLLECTORS` array) — no filesystem magic. Rules evaluate against a **small explicit
evaluation context** — indexed resources, collector coverage, snapshot identity, and an
injected `evaluatedAt` — extending today's `ExposureContext`, not a general graph object.
(A richer memoized `ResourceGraph` was considered and tabled — see `IDEAS.md` entry 10;
adopt it only if visualization or several rule consumers later need it.) Two changes:

1. **A rule is self-describing.** Extend the rule contract with metadata so the registry,
   the UI, the coverage report, and the citation harness (2e) can all read it:

   ```ts
   export interface ExposureRule {
     kind: string;
     category: "network" | "data" | "dns" | "tls" | "supply_chain" | "attack_path";
     /** Collectors whose data this rule needs; the rule is skipped (not failed) if absent. */
     requires: readonly string[];       // e.g. ["certificates", "load_balancers"]
     /** DigitalOcean doc URL(s) justifying the rule. Enforced non-empty by a test. */
     references: readonly string[];
     evaluate(context: EvaluationContext): DraftFinding[];
   }
   ```

2. **`DraftFinding` carries `references` too**, defaulting to the rule's. This is what
   makes "all sources cited" (2e) a structural guarantee rather than a promise: a finding
   literally cannot be persisted without the doc URL that backs it.

**Contributor workflow after this change** (document in `README.md`):
1. Add the API shape to `src/do/types.ts` (from the OpenAPI spec, never from memory).
2. Add a collector to `src/do/collectors.ts` (or reuse one) and a fixture.
3. Add `src/exposure/rules/<name>.ts` exporting a rule with `requires` + `references`.
4. Register it in `src/exposure/rules/index.ts` (one line).
5. Add a rule test from a literal context.

**Guardrails preserved:** rules stay pure functions of their evaluation context (no I/O),
so a finding is deterministic for the same inputs and testable from a literal. This is
**not** a claim that the persisted snapshot can replay findings: the snapshot stores
normalized, allowlisted *output*, not the raw provider objects a rule reads (see "Store
real point-in-time snapshots").

### 1b + 1c. New detections

> **Reference menu — decisions live in the addendum's [Rule revisions](#rule-revisions).**
> This section is retained for its per-rule fire conditions, severities, and DigitalOcean
> doc citations. It is **not** a build list. The addendum's Rule revisions table is
> authoritative and revises or removes ~12 of these (e.g. `database.no_private_network`
> removed, DNS takeover downgraded to a low-confidence heuristic, the plaintext-DB-URL path
> removed, egress demoted to context-only, DOKS EOL replaced by the provider `upgrades`
> endpoint). **Build from the addendum; cite from here.**

Grouped by product. Each rule lists: **fire condition**, **severity** (with the
sensitivity × reachability reasoning where the matrix applies), whether it
**proves internet exposure** (sets `is_internet_exposed`), whether it needs
**cross-resource** correlation, the **collector/type** work it requires, and a
**citation**. Rules are tiered by value and confidence.

#### DNS & networking — the "exploit through a public resource" surface

DigitalOcean-managed DNS (`/v2/domains`, `/v2/domains/{name}/records`) plus reserved IPs
(`/v2/reserved_ips`) let us detect **dangling records / subdomain-takeover risk** by
cross-referencing record targets against owned inventory — a class the current engine
cannot see and a genuinely DO-shaped finding.

| Rule | Fires when | Severity | Exposure? | Cross-res | Citation |
|---|---|---|---|---|---|
| `dns.dangling_a_record` | An `A`/`AAAA` record's `data` IP is **not** in the union of owned droplet-public / reserved / floating / load-balancer IPs | **high** — attacker can claim a pooled IP and serve content on your name | no (name-level) | yes (all IP inventory) | [domain records](https://docs.digitalocean.com/reference/api/reference/domain-records/), [reserved IPs](https://docs.digitalocean.com/reference/api/reference/reserved-ips/) |
| `dns.dangling_app_cname` | A `CNAME` to `*.ondigitalocean.app` that matches no live app `default_ingress`/`live_domain` | **medium** — random ingress suffix lowers re-registration odds | no | yes (apps) | [apps API](https://docs.digitalocean.com/reference/api/reference/apps/) |
| `dns.record_points_to_unassigned_reserved_ip` | An `A`/`AAAA` targets a reserved IP whose `droplet` is `null` | **low/medium** — fragile; becomes takeover on release | no | yes (reserved IPs) | [reserved IPs](https://docs.digitalocean.com/reference/api/reference/reserved-ips/) |
| `firewall.unrestricted_egress` | An attached firewall's `outbound_rules[].destinations.addresses` includes `0.0.0.0/0`/`::/0` on **all ports**, and the firewall protects a public droplet | **low** baseline → **medium** if the droplet is a DB trusted source (exfil path) | no (`provesInternetExposure:false`) | optional | [firewall rules](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/) |
| `firewall.broad_inbound_cidr` | An inbound source CIDR broader than `/8` but not literally `/0` (e.g. `0.0.0.0/1`) | **low** — companion to `droplet.public_ingress`, kept separate so the `/0` critical path isn't diluted | yes | no | [firewalls API](https://docs.digitalocean.com/reference/api/reference/firewalls/) |

Honesty constraints baked in:
- The dangling rules detect *"points outside owned inventory"* — a strong heuristic, not
  proof of exploitability (confirming re-registration needs active DNS/HTTP probing,
  which a read-only scan does not do). The finding text must say so.
- `firewall.unrestricted_egress` must **not** fire on a firewall with an *empty*
  `outbound_rules` array — on DigitalOcean that means deny-all egress, the opposite of the
  risk. Only the explicit all-ports `0.0.0.0/0` rule fires. Egress is near-ubiquitous
  (the console auto-populates allow-all), so baseline severity is `low` to avoid the
  alert fatigue the codebase explicitly designs against.

New collectors: `domains` (+ records per domain), `reserved_ips`. New types: `DoDomain`,
`DoDomainRecord`, `DoReservedIp`.

#### Certificates & load-balancer TLS

`/v2/certificates` is already reachable with current scopes (`DESIGN-NOTES.md` next
steps) and expiry is a cheap, real, high-value finding — especially when the cert is
bound to a public load balancer.

| Rule | Fires when | Severity | Cross-res | Citation |
|---|---|---|---|---|
| `certificate.expired` | `not_after < now` | **high** if bound to a public LB (`certificate_id` match → active TLS outage / MITM), else **medium** | yes (LB `forwarding_rules[].certificate_id`) | [certificates API](https://docs.digitalocean.com/reference/api/reference/certificates/) |
| `certificate.expiring_soon` | `now < not_after < now+30d` | **medium**; **low** for `lets_encrypt` (auto-renews) | yes | same |
| `certificate.invalid_state` | `state ∈ {error, pending}` persisting | **low → medium** if bound to a public LB (broken TLS) | yes | same |
| `load_balancer.http_no_redirect` | Public LB has an `http`/`http2` entry rule and `redirect_http_to_https == false` and no matching HTTPS rule | **medium** — cleartext transport on a public endpoint | no | [load balancers API](https://docs.digitalocean.com/reference/api/reference/load-balancers/) |
| `load_balancer.https_without_certificate` | HTTPS entry rule with no `certificate_id` and `tls_passthrough == false` | **medium** — broken/missing TLS termination | yes (certs) | same |
| `load_balancer.tls_passthrough` | Any `forwarding_rules[].tls_passthrough == true` on a public LB | **low** — legitimate design, recorded for posture | no | same |
| `load_balancer.weak_tls_policy` | `tls_cipher_policy == "DEFAULT"` on a public TLS-terminating LB | **low** — DO default; informational | no | `load_balancer_base.yml` |

New collector: `certificates`. New type: `DoCertificate`. Type additions:
`certificate_id` on `DoForwardingRule`, `tls_cipher_policy` on `DoLoadBalancer`
(`DoForwardingRule.tls_passthrough` already exists).

#### Managed databases — beyond the two current rules

| Rule | Fires when | Severity | Cross-res | Citation |
|---|---|---|---|---|
| `database.version_end_of_life` | `version_end_of_life <= now` (past EOL, unpatched) | **high**; **medium** if `<= now+90d` | no | `database_cluster.yml` (`version_end_of_life`, `version_end_of_availability` are read-only API fields) |
| `database.no_private_network` | `private_network_uuid` absent — reachable only via public endpoint | **low → medium**, compounds with permissive trusted sources | no | [databases API](https://docs.digitalocean.com/reference/api/reference/databases/) |
| `database.no_standby_single_node` | `num_nodes <= 1` (no failover) | **low** (availability) — gate behind an availability toggle | no | [add standby nodes](https://docs.digitalocean.com/products/databases/postgresql/how-to/add-standby-nodes/) |

Key win: `version_end_of_life` is **self-contained** — the API returns the EOL date
directly, so no hand-maintained version table that drifts. Prefer it over hardcoding
versions. Requires adding `version_end_of_life` / `version_end_of_availability` to
`DoDatabaseCluster`.

Rejected here, with reasons (so they stop being re-proposed):
- `connection.ssl == false` → **false positive**, TLS enforced server-side.
- "default admin user present" (`doadmin`) → fires on 100% of clusters; not a
  misconfiguration.
- backup retention / PITR config → not exposed by the read-only API.

#### Kubernetes (DOKS) — beyond the control-plane rule

| Rule | Fires when | Severity | Citation |
|---|---|---|---|
| `kubernetes.version_end_of_life` | Cluster minor version below DO's oldest supported minor | **high** if EOL; **medium** if N-2 but supported | [supported releases](https://docs.digitalocean.com/products/kubernetes/details/supported-releases/) |
| `kubernetes.workers_public_ip` | `isolated_workers == false` (or absent) — worker nodes get public IPs | **medium** — enlarges attack surface (kubelet, NodePort, SSH) | `cluster.yml` (`isolated_workers`) |
| `kubernetes.no_auto_upgrade` | `auto_upgrade == false` | **low**; **medium** if combined with an old `version` | `cluster.yml` (`auto_upgrade`) |

Honesty: the DOKS API exposes **no** EOL/deprecation flag (`options.yml` has none), so
`version_end_of_life` needs a small hand-maintained minor-support table sourced from the
docs — call that out as a maintenance dependency in the rule's comment. Per-node public
IPs are **not** in the API (`node.yml` has no IP field); `isolated_workers` is the correct
signal — do not invent a node-IP field. `surge_upgrade`/`ha`/node-pool autoscaling are
availability/cost, **not** security — do not build security rules from them.

#### App Platform & Functions — beyond ingress + plaintext secrets

The full app spec is returned by `/v2/apps`, so several config-level risks are readable.

| Rule | Fires when | Severity | Exposure? | Citation |
|---|---|---|---|---|
| `app.cors_wildcard` | `ingress.rules[].cors.allow_origins[]` (or deprecated `services[].cors`) is match-all (`exact:"*"`, catch-all `prefix`, or `regex:.*`) | **medium**; **high** when combined with `allow_credentials: true` | no | [CORS policies](https://docs.digitalocean.com/products/app-platform/how-to/configure-cors-policies/), [app spec](https://docs.digitalocean.com/products/app-platform/reference/app-spec/) |
| `app.service_public_despite_internal_ports` | A service declares `internal_ports[]` yet still has `http_port` set (public + internal) | **medium** — strong "unintended public" signal | yes | [internal routing](https://docs.digitalocean.com/products/app-platform/how-to/manage-internal-routing/) |
| `app.deploy_on_push` | Any component has `{github,gitlab,bitbucket}.deploy_on_push == true` | **low** — unreviewed-deploy / supply-chain posture | no | [app spec](https://docs.digitalocean.com/products/app-platform/reference/app-spec/) |
| `app.dev_database` | `spec.databases[].production == false` | **low** — ephemeral, unbacked-up; informational | no | [app spec](https://docs.digitalocean.com/products/app-platform/reference/app-spec/) |

Match all three wildcard forms for CORS (`exact`/`prefix`/`regex`) — the accepted syntax
for a literal `*` is not fully pinned in the docs.

**Functions blind spot:** unauthenticated public function URLs (`web: true` without
`webSecure`) are **not** in the `/v2/apps` app spec — they live in the Functions
`project.yml` build config, and per-function auth state is not exposed by a read-only v2
endpoint we could confirm. Do **not** build this rule against `/v2/apps`; record it as a
gap and revisit if the serverless namespace API is confirmed to expose it.

#### Snapshots, images, volumes

| Rule | Fires when | Severity | Citation |
|---|---|---|---|
| `image.public_shared` | `/v2/images` entry with `public == true` and `type ∈ {snapshot, backup, custom}` (a user image, not a DO base image) | **high** — disk contents (possibly baked-in secrets) exposed to all DO accounts | `image.yml` (`public` boolean) |
| `volume.unattached` | `/v2/volumes` entry with empty `droplet_ids` | **low** — mostly cost, secondarily residual-data hygiene | [volumes API](https://docs.digitalocean.com/reference/api/reference/volumes/) |
| `netip.reserved_ip.unassigned` | Reserved IP with `droplet: null` | **low** — cost/hygiene; not a takeover vector while held | [reserved IPs](https://docs.digitalocean.com/reference/api/reference/reserved-ips/) |

New collectors: `images`, and reuse of `volumes` (already collected). New type: `DoImage`.

### 1b (deterministic core). Cross-resource attack-path rules

These are the "exploit other resources through a public one" findings, expressed
**deterministically** — every hop proven by a provider-reported field, no VPC-only
inference. They belong in the engine (not only the LLM pass) because they are clean and
reproducible. They are new `category: "attack_path"` rules and each cites the DO
networking semantics that permit the hop.

Two shared primitives (built once in the evaluation context, reused by every path):
- `dropletIsInternetExposed(d, port)` = public IP present **and** (no attached firewall
  **or** an inbound rule opens `port` to `0.0.0.0/0`). Cloud firewalls are default-deny
  *only when attached* ([firewalls](https://docs.digitalocean.com/products/networking/firewalls/)).
- `databaseTrusts(d, db)` = `db` trusted sources contain `{type:droplet, value:d.id}`
  **or** `{type:tag, value ∈ d.tags}`. Adding any trusted source denies everything else
  ([secure PostgreSQL](https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/)).

| Path rule | Chain (each hop provider-proven) | Severity | Why worse than the parts |
|---|---|---|---|
| `path.exposed_droplet_trusted_by_database` | internet → droplet (sensitive port open to `/0`) → DB whose trusted sources include that droplet or its tag → data | **high**, **critical** if the open port is the DB's own protocol or SSH | The DB's trusted-source allowlist — normally a hardening *win* — is defeated because one allowed principal is itself internet-reachable |
| `path.exposed_tag_grants_trust` | internet → exposed droplet carrying tag `T` → any DB/firewall that trusts tag `T` (dynamic membership) | **high** | Tag trust is invisible in per-resource review; a different team's public droplet wearing `T` is auto-whitelisted |
| `path.db_access_plus_open_egress` | compromised droplet with DB trust **and** unrestricted egress → exfiltration channel | **medium**, **high** if the same droplet is also ingress-exposed (full ingress→data→exfil) | Neither leg is actionable alone; the pair is a complete exfil path |
| `path.app_plaintext_db_url` | app with a plaintext `postgres://…`/`mysql://…` env var whose host matches a collected DB → standing DB credentials | **high** | Leaked creds bypass the trusted-source allowlist entirely (the app is already a trusted source) |
| `path.lb_sole_ingress_sensitive_port` | internet → public LB forwarding a sensitive/admin port → backend droplet with no *direct* public exposure | **medium**, **high** for admin ports | A supposedly-private droplet is in fact internet-reachable through the LB |

**Anti-overclaim guardrail (must be a test):** shared VPC alone (`droplet.vpc_uuid ==
database.private_network_uuid`) does **not** imply database reachability — DO databases
deny all non-trusted-source connections regardless of VPC
([VPC details](https://docs.digitalocean.com/products/networking/vpc/details/)). Shared
VPC is at most an *informational context* signal that raises confidence on a path already
proven by a trusted-source entry; it never stands alone as a finding. This is the single
easiest place to produce a confidently-wrong result, so it gets an explicit negative test.

**De-duplication:** `path.lb_sole_ingress_sensitive_port` must suppress when the backend
droplet is already directly flagged, so LB and direct exposure aren't double-counted.

**Relationship to the existing LLM agent (`src/agent/run.ts`):** promoting these clean
chains to deterministic rules *narrows* the agent's job to genuinely fuzzy, novel paths —
which is the right division of labour (the spec: an LLM may explain, it cannot decide).
The agent keeps running as the exploratory layer; its output stays in a separate,
clearly-labelled panel and is never persisted as verified evidence.

---

## Part 2 — spec / product updates

### 2a. Per-snapshot JSON download

**Problem.** Export is global and current-state only (`app/api/export/route.ts` →
`buildExport`). A reviewer cannot download the exact inventory + findings a specific
historical sync produced.

**Plan.** *(Revised — read the stored snapshot; timestamp reconstruction is withdrawn.
See "Store real point-in-time snapshots" in the addendum.)*
- Parameterize `buildExport` by `syncRunId` (default: latest, preserving today's
  behaviour). Read the append-only snapshot document written for that run. Do **not**
  reconstruct state from `first_seen_at` / `last_seen_at` / `removed_at` / `resolved_at`:
  those columns cannot recover prior resource JSON, relationships, severities, or evidence
  once the rows are updated.
- Add `GET /api/export?syncRunId=<id>` and a **Download JSON** button on each row of the
  `/syncs` page (and each history entry in the drawer).
- Keep the `DigitalOceanSecurityExport` schema **byte-for-byte v1** — its seven top-level
  keys are the one compatibility contract, guarded by `tests/export.test.ts`. Do **not**
  add a `snapshot` key to the envelope, and do **not** surface the `trusts` edge in the
  exported `relationships` (whose enum is frozen at four values). Expose run identity
  out-of-band instead: `syncRunId` / `status` / `coverage` ride in response headers and the
  `Content-Disposition` filename (`do-export-<syncRunId>.json`). The self-describing run
  metadata and the `trusts` edge live on the separate internal snapshot document (own
  `snapshotVersion`), never in the evaluator-facing v1 envelope. (Carrying either in the
  export is a future `schemaVersion: "2"` decision, out of scope here.)
- Test: the export for run *N* still matches the frozen v1 shape (existing test unchanged),
  and is built from the snapshot document persisted by run *N* rather than a mutable
  current-state row.

### 2d. Visualize vulnerabilities & relationships

**Problem.** Risk is currently only tables. The relationships (`src/relationships/derive.ts`)
and the new attack-path rules are inherently a graph; a picture makes blast radius legible.

**Plan.**
- A **resource-relationship graph** on a new `/graph` page (and embedded on resource
  detail): nodes = resources coloured by sensitivity, edges = `contains` / `attached_to`
  / `routes_to` / `depends_on`. Node badges show exposure and highest finding severity.
- **Attack-path overlay:** render each `category:"attack_path"` finding as a highlighted
  entry → pivot → target chain over the same graph, so "exploit through a public
  resource" is shown, not just described.
- **Server-rendered, shareable, deterministic** — same discipline as the filters
  (`README.md`): the graph is derived from stored data with a stable layout seed, no
  client-only state, so a URL reproduces a view. Data comes from the **internal snapshot
  document**, not the v1 export envelope — the graph needs the `trusts` edge, which the
  frozen export does not carry. Both derive from the same stored sync, so the picture and
  the downloaded JSON never contradict on the resources and relationships they share.
- Keep it honest: unassessed resources render with the existing dashed "not assessed"
  treatment; the graph must not imply completeness it doesn't have.
- Library: a lightweight deterministic renderer (e.g. server-built graph → SVG, or a thin
  client layer fed a precomputed layout). Avoid a heavy client graph engine that would
  reintroduce client state.

### 2e. Enforce a citing, non-hallucinating, fix-recommending harness

This spans both the deterministic engine and the LLM pass. The principle: **a finding
that cannot point at its evidence and its fix does not ship.**

**Deterministic findings.**
- `references: string[]` becomes **required** on every rule (see 1a). A test asserts
  every registered rule declares at least one DigitalOcean doc URL, and every emitted
  finding carries it **inside the finding's `evidence` object** — the frozen v1 export's
  `evidence: Record<string, unknown>` field — so citations ride the existing contract with
  no new top-level key. A dedicated internal column is permitted only if the export builder
  omits it, keeping v1 byte-for-byte. That is "all sources cited" as a structural invariant.
- `remediation` is already required on `DraftFinding`; add a test that it is non-empty
  for every rule — "recommends required fixes," enforced.

**LLM pass (`src/agent/run.ts`, `src/agent/tools.ts`).** The agent already reads only the
stored snapshot and is told to cite only what it retrieved. Harden this into enforcement:
- **Grounding validator (anti-hallucination).** After the agent calls `report_findings`,
  reject any finding whose `resourceExternalIds` were not actually returned by a
  `query_*` tool call this run, or whose `supportingFindingKinds` don't exist in the rule
  findings. Today the loop trusts the model's self-restraint; make it a hard post-filter
  (the `withRepeatGuard` layer already proves we can wrap tool I/O — reuse the recorded
  tool results as the ground-truth set).
- **Required remediation.** Add a required `remediation` field to the `report_findings`
  schema so an agent finding without a concrete fix is invalid input, not a warning.
- **Required citations.** Add a required `citedResourceIds` / evidence field the validator
  checks against retrieved data; drop findings that cite nothing verifiable.
- **Separation stays.** Agent findings remain visually and structurally distinct from
  rule findings and are never written into `exposure_findings` as verified evidence
  (`digitalocean-cloud-inventory.md`: "Never show an LLM-only claim as verified
  evidence").
- **Provenance in prompt.** The system prompt already treats resource names/tags/specs as
  untrusted data; keep that and add the validator as the belt to its suspenders.

---

## Collectors & types to add (summary)

| New collector | Endpoint | Required? | Feeds rules |
|---|---|---|---|
| `certificates` | `/v2/certificates` | optional | `certificate.*`, LB TLS |
| `domains` (+ records) | `/v2/domains`, `/v2/domains/{name}/records` | optional | `dns.*` |
| `reserved_ips` | `/v2/reserved_ips` | optional | `dns.*`, `netip.reserved_ip.unassigned` |
| `images` | `/v2/images?private=true` | optional | `image.public_shared` |

New types in `src/do/types.ts`: `DoCertificate`, `DoDomain`, `DoDomainRecord`,
`DoReservedIp`, `DoImage`. Field additions: `version_end_of_life` /
`version_end_of_availability` on `DoDatabaseCluster`; `auto_upgrade` / `isolated_workers`
on `DoKubernetesCluster`; `certificate_id` on `DoForwardingRule`; `tls_cipher_policy` on
`DoLoadBalancer`. All taken from the OpenAPI spec, never from memory.

Every new collector is `required: false`, so a failure yields a *partial* sync with
visible coverage, never a lost one — the existing contract.

---

## Suggested phasing

> **Superseded — see the addendum's [Revised implementation order](#revised-implementation-order).**
> The original five-phase list here treated `ResourceGraph` as foundational and named a
> `kubernetes.version_end_of_life` rule, both of which the addendum overturned. It is
> removed so exactly one implementation order remains authoritative: the addendum's, which
> is correctness-first (effective firewall policy, coverage-aware reconciliation, confidence
> and exposure metadata, append-only snapshots) before any new rule ships.

## Testing additions

- Every rule: fires and does-not-fire from a literal evaluation context; declares ≥1
  reference; non-empty remediation.
- The `ports:"0"` trap already exists — add an analogous **empty-`outbound_rules` =
  deny-all** trap for the egress rule.
- Attack paths: one positive per path + the **shared-VPC-alone must not fire** negative.
- Harness: a hallucinated agent finding (cites a resource never retrieved) is dropped;
  an agent finding with no remediation is rejected.
- Export: per-snapshot reconstruction is point-in-time correct.

---

## Open questions to confirm before building

- **DNS dangling confidence.** Read-only detection is "points outside owned inventory,"
  not proven takeover. Ship as `high` heuristic with explicit finding text, or gate
  behind an optional active-probe step? (Recommend: ship as heuristic, text says so.)
- **DOKS EOL table.** The API exposes no lifecycle flag, so a hand-maintained minor-support
  table is unavoidable. Acceptable maintenance cost, or defer the DOKS-version rule?
- **Availability rules** (`database.no_standby_single_node`, backups) — in scope for a
  security tool, or behind an explicit "availability posture" toggle so they don't dilute
  the security report? (Recommend: toggle.)
- **Graph library** for 2d — server-built SVG vs. a thin precomputed-layout client. Trades
  interactivity against the "no client state" discipline.

---

## Evaluation addendum (2026-08-26)

This addendum refines the plan after reviewing the current implementation, current
DigitalOcean documentation, and recent incident/vulnerability reports. Where this
section conflicts with an earlier proposal, **this addendum takes precedence**.

### Product boundary: identify and explain, never modify

The product is a read-only weakness-identification and remediation-guidance tool. It
must not make changes to a customer's DigitalOcean environment.

- Use only read operations against DigitalOcean APIs. Do not add mutation tools or
  remediation-execution endpoints.
- Never request broader credentials in order to remediate a finding.
- Label every proposed change **"Recommendation only - no changes were made."**
- Commands and API examples are copyable guidance for an authorized operator, never
  executable actions in this application.
- A finding is resolved only after a later read-only sync observes that its evidence is
  gone. Clicking an acknowledgement or reading the instructions does not resolve it.
- Collector failure or missing permission is reported as incomplete coverage, never as
  a clean result.

Specific remediation guidance is still a core requirement. Each deterministic rule
owns a remediation template so the authoritative fix is not invented by the LLM:

```ts
type RemediationGuide = {
  summary: string;
  prerequisites: string[];
  consoleSteps: string[];
  cliExample?: string;       // display/copy only; never executed
  validationSteps: string[]; // what the next read-only scan should observe
  rollbackNotes?: string[];
  references: string[];
};
```

The instructions must be resource-specific. For example, a public database-port
finding should name the firewall, attached resource, protocol, port range, effective
source CIDR, and any higher-precedence deny rules. Its fix must tell the operator to add
the required narrow source first, verify connectivity, then remove the broad allow rule.
This avoids turning generic hardening advice into an outage.

### Phase 0: correctness before new rules

The following work precedes the earlier Foundation phase.

#### Effective Cloud Firewall policy

DigitalOcean Cloud Firewalls now support `allow` and `deny` actions, with deny rules
taking precedence across all firewalls applied to a Droplet. The rule model and
evaluator must capture `action` before any new exposure rule ships.

The evaluator must account for:

- allow and deny precedence across multiple attached firewalls;
- protocol and port-range intersections;
- IPv4 and IPv6 independently;
- split CIDRs that collectively cover the Internet;
- allow ranges partially reduced by deny ranges; and
- the distinction between "network path permitted" and "service confirmed listening."

References:

- [Configure firewall rules](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/)
- [DigitalOcean Networking updates](https://docs.digitalocean.com/products/networking/)

#### Coverage-aware evaluation and reconciliation

An empty resource array currently cannot tell the engine whether collection succeeded
and found nothing or failed and found nothing. Add collector coverage to the evaluation
context. A rule's `requires` metadata gates both creation and resolution:

- Do not run an absence-based rule unless every required dataset is authoritative.
- Do not resolve a cross-resource finding unless every dataset that supported it was
  collected successfully in the current sync.
- Track per-domain DNS-record coverage if one domain can fail while other domains
  succeed.
- Treat HTTP 403, missing OAuth scope, pagination failure, and provider/API errors as
  unknown coverage rather than empty inventory.

#### Evidence confidence is separate from severity

Add a required confidence/evidence classification to each finding:

- `provider_reported` - directly stated by a DigitalOcean response;
- `derived` - deterministically inferred from complete provider data;
- `active_probe` - observed by an explicitly enabled read-only network/DNS check; or
- `heuristic` - suspicious but not sufficient to prove exploitability.

Severity describes impact. Confidence describes how strongly the evidence supports the
claim. A high-impact heuristic must not be presented as a verified high-severity
exposure.

Make `provesInternetExposure` required, or default it to `false`. Lifecycle,
availability, and configuration-quality findings must not silently count as verified
Internet exposure. Add an injected `evaluatedAt` from the sync run so certificate and
EOL rules remain deterministic for the same snapshot.

#### Severity model v2 — richer, still explainable

Today severity is a pure two-input lookup: `MATRIX[sensitivity][reachability]` → one of
four levels (`src/exposure/severity.ts`). That is deterministic and explainable, which is
exactly right, but "robust" here should mean *more legible inputs*, **not** a weighted
numeric risk score. A floating "7.3" is unauditable, and this tool's whole value is that a
finding survives "prove it." So the model stays a discrete lookup plus **named, bounded,
ordered modifiers**, clamped to the same four levels, with the derivation recorded so it
can be shown. Three changes:

1. **Confidence is a separate axis from severity** (see the previous subsection).
   `Confidence ∈ {provider_reported, derived, active_probe, heuristic}` describes how
   strongly the evidence supports the claim; severity describes impact. A high-impact
   *heuristic* (stale DNS) must never render as a verified critical. Every finding carries
   both.

2. **Impact inputs gain explicit, discrete modifiers** — each a `{label, delta, reason}`,
   applied in order, `rank` clamped to `[low, critical]`, every step retained:
   - **authenticated vs unauthenticated** surface (an open but credentialed endpoint —
     k8s API, a managed DB still demanding a password — is lower impact than an anonymous
     one like a public Spaces listing);
   - **blast radius** (a DB trusted by many resources, or a tag-firewall covering N
     droplets → bounded `+1` past a threshold);
   - **environment** (DO projects expose an `environment` field of
     Development/Staging/Production — a production resource legitimately outranks a dev
     one; provider-reported and citeable);
   - **attack-path composition** (chain severity = `max(hop severities)`, then `+1` when
     one droplet is both entry and exfil).

3. **The derivation is stored and displayed.** `deriveSeverity()` returns
   `{ sensitivity, reachability, base, modifiers, final, formula }`; the human-readable
   `formula` (e.g. *"datastore data × sensitive-port reachability ⇒ critical"*) plus the
   `confidence` are surfaced **inside each finding's `evidence`**, so they persist, export,
   and render through the existing evidence panel with no schema migration and no change to
   the export contract (whose top-level finding keys are pinned by a test).

**Display placement.** Show the full derivation + a confidence chip on the **exposure /
finding detail** ("the thingy") — it is nearly free once stored and makes every severity
auditable. Do **not** add a formula column to the **inventory** table: a resource's
"severity" is just its worst finding, and a per-row formula is noise. Keep the inventory's
sensitivity/exposure badges; a hover tooltip with the one-line formula is an optional
follow-up. Show the confidence chip anywhere severity appears, so heuristic findings read
as visibly distinct from proven ones.

*Implementation note: the engine layer of this (the `deriveSeverity` mechanism, the
confidence axis, and surfacing both through `evidence`) is the first slice being built —
modifiers ship as a mechanism with no rule wiring yet, so base severity is unchanged and
existing tests stay green; individual rules opt into modifiers as their inputs
(project environment, resolved trust graph) become available.*

#### Store real point-in-time snapshots

`first_seen_at`, `last_seen_at`, `removed_at`, and finding resolution timestamps cannot
reconstruct prior resource JSON, relationships, severities, or evidence after those rows
are updated. Do not implement timestamp-based reconstruction as described earlier.

Store one append-only, sanitized snapshot document per run that updates current state —
**including a `partial` run**, not only a fully successful one, since a partial run still
mutates current state and its export must match what it wrote. Snapshot export, historical
comparisons, agent validation, and visualization all read from that same document.
Introduce versioned individual rows only if historical ad hoc querying later proves
necessary.

**It is the post-reconciliation account view, not just this run's observations.** A
partial sync keeps last-known-good rows from a failed collector while replacing the
datasets that succeeded (`src/sync/run.ts`). The snapshot must materialize that same merged
current-state view — what the UI and tables show — so the three never diverge.

Freshness is **per item, not just per portion**, and covers resources and relationships,
not only findings. Every resource and every relationship (edge) in the snapshot carries
**`coverageKeys: string[]` — every dataset its derivation depended on — not a single key**,
plus whether it was **observed this run** or **retained from a prior run** because one of
those collectors did not succeed. A derived edge routinely spans several datasets: a
tag-based `trusts` edge depends on both `database_firewall:<clusterId>` and `droplets` (the
tag is resolved to concrete Droplets), and a `depends_on` edge depends on `apps` and
`databases`. An edge is live only when **all** of its `coverageKeys` are authoritative in
the current sync; if any is stale the edge is retained-but-stale. Without this a reader
cannot tell a live `trusts` edge from a stale one carried over from a failed
database-firewall call, and an attack path could be asserted over an edge that no longer
holds. The embedded coverage summary still marks which portions are fresh versus
stale-but-retained versus not assessed;
the per-item markers make the same distinction resolvable down to a single edge or resource.

**It is an immutable evaluated-output document, not a replay input.** It stores normalized
output — resources, relationships (including `trusts`), findings with evidence/confidence/
severity derivation, and coverage — **not** the raw provider objects a rule read. It
therefore cannot, and does not promise to, re-derive findings from scratch; adding
sanitized evaluation inputs is a later step to take only if replay ever becomes a
requirement.

**Payload contract (required before this ships).** The document is an *allowlisted,
versioned projection*, never the raw inventory:

- **Allowlist, do not dump.** Reuse the existing metadata-allowlist discipline
  (`src/normalize/metadata-allowlist.ts`): carry the same normalized fields the database
  already stores, plus derived relationships, findings (with evidence, confidence, and the
  severity derivation), and coverage. It **must never** copy an App Platform `spec` or any
  GENERAL env var — those are returned in plaintext by `/v2/apps` (`src/do/types.ts`,
  `DoAppEnvVar`), and persisting them would leak third-party credentials the collector path
  deliberately refuses today.
- **Versioned.** A `snapshotVersion` distinct from the export `schemaVersion`, so the
  stored shape can evolve without touching the export compatibility contract.
- **Self-describing.** Embed `syncRunId`, run `status`, and per-collector `coverage` (the
  same keys used for finding coverage) so a reader tells assessed from not-assessed without
  a second query.
- **Atomic.** Written in the same transaction that updates current state, so a snapshot and
  the rows it describes can never disagree, and a run failing mid-write leaves no partial
  document.

### Rule revisions

| Earlier proposal | Revised decision |
|---|---|
| `database.version_end_of_life` | Keep. Prefer provider fields `version_end_of_life` and `version_end_of_availability` over a local lifecycle table. |
| `database.no_private_network` | Remove as written. A cluster receives a default VPC when none is specified, and missing VPC data can be a permission/coverage issue. |
| `kubernetes.version_end_of_life` | Rename to **`kubernetes.upgrade_available`**, driven by the provider `upgrades` endpoint (possible target versions, or `null`) plus exact patch status. An available upgrade does **not** prove the installed release is unsupported — make **no EOL/"unsupported" claim without explicit lifecycle evidence**; distinguish patch from minor upgrades, and note auto-upgrade covers patches only. No hand-maintained minor-version table. |
| `kubernetes.auto_upgrade_disabled` | Keep, but state that auto-upgrade covers patches rather than minor-version upgrades. |
| `kubernetes.public_workers` | Fire only when `isolated_workers` is explicitly `false`; absent is unknown. |
| `dns.a_points_to_unowned_ip` | Do not call an external IP a takeover: external hosting is normal. Require evidence of a deallocated owned target or an active check; otherwise report a low-confidence stale-DNS heuristic. |
| unmatched `ondigitalocean.app` target | Do not assume it is claimable. Account for App Platform domain verification and certificate ownership. |
| `netip.reserved_ip.unassigned` | Informational only. An unassigned Reserved IP is still held by the account and is not attacker-claimable until released. |
| unrestricted egress | Do not emit as a standalone high-severity weakness. Use it as context only when a concrete compromise path already exists. |
| broad inbound CIDR | Keep only after effective allow-minus-deny evaluation exists. Prefix length alone is insufficient. |
| certificate expiry | Keep as availability/trust failure. Do not claim expiration alone proves MITM. Escalate only when the certificate is actively bound to a public endpoint. |
| LB HTTP without redirect | Report only when HTTPS intent is established. HTTP-only service can be deliberate. |
| LB TLS passthrough | Inventory/context, not a finding; it is a supported design. |
| LB sensitive backend port | Keep only when frontend firewall, forwarding rule, and backend firewall collectively permit the path. |
| App `deploy_on_push` | Remove or informational only; it is normal platform behavior. |
| App public despite `internal_ports` | Informational context. Public and internal routes can intentionally coexist. |
| App wildcard CORS with credentials | Split literal wildcard from broad regex/reflected-origin behavior and verify provider behavior before assigning high severity. |
| plaintext DB URL attack path | Remove. Credentials do not bypass trusted-source network controls, and inspecting secret values conflicts with secret minimization. |
| `image.public_shared` | Deprioritize. A public image returned by the private-images endpoint is more useful as a provider-contract anomaly than a Phase 2 exposure rule. |
| single-node, backup, and development-database findings | Place behind an explicit resilience/availability posture mode so they do not dilute exposure results. |

Database attack paths must evaluate every supported trusted-source form: Droplet,
Kubernetes cluster, App, tag, exact IP, and IP/CIDR ranges intersecting relevant private
resource addresses. Shared VPC membership alone is not a trust edge, but an explicitly
trusted VPC CIDR can be one.

References:

- [Databases API](https://docs.digitalocean.com/reference/api/reference/databases/)
- [Secure PostgreSQL clusters](https://docs.digitalocean.com/products/databases/postgresql/how-to/secure/)
- [DOKS upgrades](https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/)
- [DOKS supported releases](https://docs.digitalocean.com/products/kubernetes/details/supported-releases/)
- [App Platform internal routing](https://docs.digitalocean.com/products/app-platform/how-to/manage-internal-routing/)
- [App Platform domains](https://docs.digitalocean.com/products/app-platform/how-to/manage-domains/)
- [Reserved IP limits](https://docs.digitalocean.com/products/networking/reserved-ips/details/limits/)
- [Load Balancer SSL passthrough](https://docs.digitalocean.com/products/networking/load-balancers/how-to/ssl-passthrough/)

### Incident-informed checks and declared blind spots

The 2022 DigitalOcean/Mailchimp incident showed that account email exposure and password
reset attempts can be part of the attack path; DigitalOcean reported that 2FA prevented
compromise of targeted accounts. Add a manual-controls/coverage section for controls the
resource API cannot reliably assess:

- required secure sign-in and 2FA;
- predefined and custom team-role review;
- API token scope and rotation review;
- team security-history review;
- security-contact review; and
- spend and outbound-bandwidth alerts for detection and cost containment.

Do not state that DigitalOcean has no IAM. DigitalOcean now provides predefined and
custom team roles, although not all role administration is exposed through API/CLI.
These checks may therefore remain declared manual attestations rather than automated
findings.

**Manual attestation is the floor, not the ceiling (deferred — see `IDEAS.md` entry 9).**
The contemplated path past it: model a *principal* — team member, token, Spaces key,
service account — as a first-class node with `can-access` edges, so the same
deterministic traversal that powers the attack-path rules also produces an *entitlement*
blast radius ("this token reaches that `datastore` cluster it never otherwise touches").
Entitlement is the fourth axis the engine does not yet have; it already computes
sensitivity, exposure, and reachability. Because DO's API cannot enumerate principals
(the two identity rows in the Confirmed-blind-spots table), that node set would be
sourced from manual upload first and an IdP/SCIM sync (Okta, Entra ID, Google Workspace)
later — never from DigitalOcean, and never from a CRM. This is **out of scope for this
plan** — which stays read-only, DO-API-grounded, and near-term — and is deliberately
deferred. It is noted here only so the "remains manual" framing above is not read as
"cannot ever be assessed," and because the `can-access` edge would extend the same
relationship model (`src/relationships/derive.ts`) and graph visualization (2d) this plan
already builds.

Recent Kubernetes vulnerabilities also define an important collection boundary.
IngressNightmare included unauthenticated ingress-nginx remote code execution, and DOKS
later added worker-node metadata-service blocking in platform patches. Account-level
DigitalOcean inventory can assess cluster version, available upgrades, public workers,
and auto-upgrade posture, but it cannot prove the installed in-cluster ingress-nginx
version or user network policies. Report that as an explicit blind spot. Do not claim
CVE detection without an optional, separately authorized Kubernetes read-only collector.

References:

- [DigitalOcean response to the Mailchimp incident](https://www.digitalocean.com/blog/digitalocean-response-to-mailchimp-security-incident)
- [DigitalOcean team roles](https://docs.digitalocean.com/platform/teams/roles/)
- [DigitalOcean custom roles](https://docs.digitalocean.com/platform/teams/roles/custom/)
- [Kubernetes IngressNightmare advisory](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- [DOKS changelog](https://docs.digitalocean.com/products/kubernetes/details/changelog/)

### LLM grounding revision

Validate agent findings against the selected stored snapshot, not merely against whether
a resource appeared in any broad tool result. For every proposed path:

1. The entry resource has a verified exposure finding.
2. Each hop's `viaRelationship` edge exists in the snapshot, in the stated `viaDirection`,
   between the previous node and this one, **and every key in that edge's `coverageKeys` is
   authoritative in the run being validated** — a retained-but-stale edge is rejected, not
   accepted merely because the row exists.
3. The target has a deterministic sensitive-resource classification.
4. Every cited `(resourceExternalId, findingKind)` pair exists.
5. The agent run records the `syncRunId` or snapshot hash used for validation.

Cite via the ordered typed hops defined in *Contracts to pin before build* — each hop
`{resourceExternalId, viaRelationship?, viaDirection?, findingKind?}` is itself the
citation the validator checks, proving both the node and the edge that reached it — rather
than a flat `resourceExternalIds` array or a duplicate `citedResourceIds` field. LLM
remediation is explanatory and clearly labeled as a suggestion; the deterministic rule's
remediation remains authoritative.

### Visualization decision

Do not add Chart.js for step-by-step remediation. Chart.js is designed for quantitative
charts, is not currently installed, and does not make a procedural fix easier to follow.
Use the existing React and CSS stack for a compact remediation stepper:

```text
Weakness -> Exact evidence -> Recommended fix (not applied) -> Verify next scan
```

Use simple attack-path cards before building a general graph:

```text
Internet -> effective firewall allow -> workload -> explicit trust edge -> datastore
```

Chart.js can be reconsidered only when stored snapshots provide meaningful quantitative
data such as severity distribution, evidence-confidence breakdown, collector coverage,
or findings introduced/resolved over time. A full interactive node graph should wait
until real accounts regularly produce paths complex enough that cards are insufficient.

### Contracts to pin before build (review resolution, 2026-08-26)

A correctness review found four places where an addendum requirement had no
representation in the code it depends on. Each is a concrete contract for Phase 0 / Phase
1 below, not a new feature. The storage-facing ones — the `trusts` relationship value, the
finding `coverage_keys` column, and the per-run snapshot document — are declared in the
canonical spec's *Internal schema extensions* section (`digitalocean-cloud-inventory.md`)
as internal-only additions the frozen v1 export omits, so plan and spec agree.

**Typed database-trust edge (`src/relationships/derive.ts`).** The `path.*` rules and the
path cards render an "explicit trust edge", but the relationship model has only
`contains | attached_to | routes_to | depends_on` — no trust. Add a `trusts`
`RelationshipKind` derived from **database firewall trusted sources**. It is emphatically
**not** DigitalOcean team membership, which `derive.ts` must still never read. It must
represent every trusted-source form — Droplet, Kubernetes cluster, App, tag, exact IP, and
IP/CIDR — with the two existing fields used correctly:

- **`evidence` (the `provider_reported | derived` enum) reflects how the edge was
  obtained, not the trust form.** A direct Droplet/App/Kubernetes trusted source is
  `provider_reported`; a tag or CIDR that had to be *resolved* to the concrete resources it
  currently matches is `derived` (membership can change, so the resolution is an inference).
- **The trust form itself (`droplet` / `tag` / `ip` / `cidr` / …) and the raw matched
  value go in `metadataJson`**, the free-form bag — never in the enum-valued `evidence`
  field.

One edge feeds both the deterministic `path.*` rules and the 2d graph, so trust has a
single source of truth. It is **internal** — it lives in the relationships table, the
snapshot, and the graph, but is **not** emitted in the frozen v1 export. Shared VPC
membership is still **not** a trust edge; an explicitly trusted VPC CIDR is.

**Per-finding coverage keys — and who produces them.** Rule-level `requires` is too coarse
to reconcile safely: resolution today recovers a finding's resource *type* from its
external id (`src/sync/run.ts`) and resolves as soon as that type is authoritative — even
if a collector supporting another hop failed, and even though database firewalls are
per-cluster child calls. Persist the **concrete coverage keys a finding actually depended
on** on the finding row (e.g. `["droplets","firewalls","database_firewall:<clusterId>"]`)
and resolve it only when **every** key is authoritative in the current sync.

This needs a **producer contract**, because collectors currently return `void` and the
orchestrator marks an entire collector authoritative by its static `resourceTypes`
(`src/do/collectors.ts`, `src/sync/run.ts`). Give a collector a way to report the granular
coverage keys it actually completed — the collector-name key for whole-dataset collectors,
plus per-child keys like `database_firewall:<clusterId>` emitted as each child call
succeeds (a collector that fetches five clusters' firewalls but fails the sixth reports
five authoritative child keys, not the whole set). The sync run accumulates these
authoritative keys into coverage; a rule records the subset it read as the finding's
`coverageKeys`; and the snapshot's coverage carries the same key space, so reconciliation,
findings, and snapshot all agree on what was authoritative. This replaces the type-only
reconciliation for any finding that sets `coverageKeys`.

**Derived relationships carry the same `coverageKeys: string[]`, for the same reason.** A
derived edge routinely spans several datasets — a tag-based `trusts` edge depends on both
`database_firewall:<clusterId>` and `droplets` (the tag is resolved to concrete Droplets), a
`depends_on` edge on `apps` and `databases` — so a single key cannot describe its freshness.
`deriveRelationships` records every dataset an edge read, and the agent accepts the edge only
when **all** of those keys are authoritative in the run being validated (see *LLM grounding
revision*, step 2); otherwise the edge is retained-but-stale and a path over it is rejected.

**Structured agent citations.** `AgentFinding` and the `report_findings` tool schema store
`resourceExternalIds` and `supportingFindingKinds` as two unrelated arrays, which cannot
express the `(resourceExternalId, findingKind)` pairs the grounding validator checks — and
even a paired form would only prove the *nodes*, never which edge the path claims to
traverse between them. Replace both with an **ordered array of typed hops** that names the
incoming edge:

```typescript
{
  resourceExternalId: string;        // the node reached at this hop
  viaRelationship?: RelationshipKind; // edge traversed to reach it (routes_to, trusts, …); absent on the entry hop
  viaDirection?: "outbound" | "inbound"; // orientation of the stored edge relative to travel; absent on the entry hop
  findingKind?: string;              // supporting rule finding at this node, if any
}[]
```

**`viaDirection` has one fixed meaning, defined against the stored directed edge.** Every
relationship row is stored as `source_external_id → target_external_id`. Relative to the
previous hop's node:

- `"outbound"` — the previous node is the edge's **`source`** and this hop's node is its
  **`target`** (travel follows the edge's stored direction).
- `"inbound"` — the previous node is the edge's **`target`** and this hop's node is its
  **`source`** (travel is against the stored direction).

The validator resolves the edge by `(previousNode, thisNode)` mapped to
`(source, target)` per that rule, so the emitter and the validator can never disagree about
which stored row a hop refers to. This is simultaneously the chain, the citations, and what
the validator verifies hop-by-hop: the entry hop has no incoming edge (so `viaRelationship`
and `viaDirection` are absent), and every later hop names an edge the validator confirms
exists in the snapshot in the stated direction. (This is the hop the *LLM grounding
revision* now cites.)

**Required confidence and exposure.** `DraftFinding.confidence` and `provesInternetExposure`
are optional today and exposure defaults to `true` (`src/exposure/types.ts`), so a
non-exposure finding silently reads as internet-exposed unless a rule remembers to opt out.
Make **both required**. A finding built from more than one provider fact (public IP *and*
effective firewall policy) is `derived`, never `provider_reported`; reserve
`provider_reported` for a single directly-stated field. Every rule already sets
`confidence`, so this is a type change plus a test, not a migration.

### Revised implementation order

1. **Correctness:** firewall actions/effective policy, coverage-aware execution and
   resolution, confidence metadata, explicit exposure classification, `evaluatedAt`, and
   append-only sanitized snapshots.
2. **High-confidence weaknesses:** database lifecycle, provider-reported DOKS upgrades,
   DOKS patch/auto-upgrade posture, certificate expiration, and effective LB/firewall
   sensitive-port paths.
3. **Cross-resource paths:** public entry to explicitly trusted workload to sensitive
   datastore, including tag, App, Kubernetes, exact-IP, and CIDR trust forms.
4. **Heuristics and manual posture:** stale DNS with appropriately low confidence,
   account secure-sign-in/role/token review, monitoring alerts, and resilience checks.
5. **Product presentation:** snapshot export and remediation/path cards first; trend
   charts and a full graph only after the underlying historical data and user need exist.

The earlier generic `ResourceGraph` plugin design is tabled (see `IDEAS.md` entry 10),
not foundational. The existing explicit rule registry can use a small evaluation context
containing indexed resources, collector coverage, snapshot identity, and `evaluatedAt`. Add a more
general graph abstraction only if multiple real consumers require behavior that this
context cannot provide.
