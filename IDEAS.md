# Ideas and deferred features

Things considered while building this and deliberately not shipped. Each entry says
what it buys, what it costs, and what would have to be true to build it.

Nothing here is a commitment. Some of it is probably a bad idea — it is written down
so the bad ones can be argued down explicitly rather than re-proposed every quarter,
and because a bad idea stated plainly is often one step from a good one.

---

## 1. Write-scope detection on a pasted token

**Idea.** DigitalOcean exposes no token introspection, so you cannot tell whether a
token given to you is read-only or can delete droplets. But you can infer it: send
`POST /v2/tags` with a body that omits the required `name`. A read-only token is
refused at authorization (403); a write-capable token gets past authorization and is
refused by validation (422). Nothing is created either way.

**Buys.** A "this token is more powerful than we need" warning at connect time.

**Costs.** A tool whose entire promise is "we never touch your infrastructure" would
be sending a write request, visible in the customer's own audit log. Its safety also
depends on DigitalOcean validating *after* authorising — true today, not a documented
contract, and a silent resource-creation bug if that order ever flips.

**Recommendation: don't.** The deciding argument is not the risk, it is that the
finding's remediation is identical to the advice you would give anyway. The output is
"your token has write scope"; the fix is "create a read-only one". You can say that at
connect time for free. Detection adds nothing the instruction does not.

**Trigger.** None. If a third party is supplying tokens, OAuth (below) removes the
question entirely rather than answering it.

**To see the result once, without shipping anything:**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://api.digitalocean.com/v2/tags" \
  -H "Authorization: Bearer $DIGITALOCEAN_TOKEN" -H "Content-Type: application/json" -d "{}"
```

---

## 2. OAuth connection

**Idea.** Register one OAuth application; customers click connect and approve on
DigitalOcean's consent screen. We never see a pasted credential.

**Buys.** Three things a pasted token cannot give you. *We* choose the scopes, so a
customer physically cannot over-grant. Tokens expire in 30 days and refresh on their
own. Revocation is one click in the customer's own account settings.

**Costs.** An OAuth app registration, refresh handling (DigitalOcean's refresh tokens
are single-use — concurrent refreshes race and the loser permanently breaks the
connection, so refresh must hold a row lock), and reactive revocation handling since
DigitalOcean sends no webhook.

**Answered.** OAuth does **not** use the granular scope namespace. Requesting
`scope=api:read` produces a consent screen reading "REQUIRES THE FOLLOWING ACCESS:
READ", and the token response returns `scope: "read"` — not `api:read`, and not
`droplet:read`. DigitalOcean's OAuth still uses the coarse `read` / `write` scopes;
the granular list the docs link to applies to personal access tokens only.

Practically this costs nothing: `read` grants every read the scanner needs. But it
means OAuth cannot be used to request *less* than full read access, so "least
privilege" here means read-vs-write, not per-resource.

**Built.** The flow is implemented — authorize redirect, single-use hashed state with
a thirty-minute window, code exchange, AES-256-GCM token storage, and an automatic
first sync. Tokens expire after 30 days and a refresh token is returned.

**Trigger.** Done for a single connection. Multi-tenant is entry 3.

---

## 3. Multi-tenant

**Idea.** Many organisations, each with their own connection and their own scan data.

**Buys.** It is the product, rather than a tool one team runs.

**Costs.** Sign-in and organisations, authorization on every route, per-connection
transports instead of one environment token, tenant columns on every table, row-level
security, and cross-tenant isolation tests as a release gate. The scanning engine
itself is unaffected — it already talks to a transport interface rather than reading
the environment.

**Trigger.** Anyone outside the team needs their own view.

---

## 4. KMS-held master key

**Idea.** Move the credential-encryption master key from an environment variable into
a managed KMS (Vault Transit, or an AWS symmetric key).

**Buys.** A stolen database backup is already inert with either option. What KMS adds
is the case where an attacker reads *both* the database and our config: with an
environment key they hold every customer credential permanently and silently; with KMS
they can only decrypt while they retain access, cannot exfiltrate the key, and every
decrypt is logged. It is also the answer customers expect in a security review.

**Costs.** A KMS dependency and one class implementing `wrapDek` / `unwrapDek`. The
schema, ciphertext format, and every call site are unchanged, and rows carry a
`key_version` so both can coexist during migration.

**Trigger.** Storing anyone else's credential. Not needed while single-tenant.

---

## 5. Spaces bucket assessment

**Idea.** Detect publicly readable object storage — the classic leaky-bucket breach.

**Costs.** DigitalOcean's v2 API cannot list buckets or read their ACLs; that lives in
the S3-compatible API behind a separate Spaces key pair. So buckets must be named
explicitly, and a second credential is involved. Detection itself needs no credential
at all — an unauthenticated request that returns a listing is proof by demonstration.
The credential only buys enumeration.

**Partially built.** `SPACES_BUCKETS` enables it today, keys are verified against
their grants before use, and an account-wide or write-capable key is refused outright.
What is missing is enumeration, which appears to require a full-access key — the exact
thing we refuse.

**Unverified.** Whether `{"bucket": "", "permission": "read"}` is accepted when
creating a Spaces key. If it is, read-all-without-write exists and the whole tradeoff
disappears. Undocumented either way; one API call settles it.

**Trigger.** A customer stores anything sensitive in Spaces, which is most of them.

---

## 6. LLM reasoning agent

**Idea.** An agent loop over the stored snapshot, looking for escalation paths that
span several resources — a public droplet sharing a VPC with a database whose firewall
trusts that droplet. Chains the deterministic rules cannot express.

**Buys.** Findings a single-resource rule engine structurally cannot produce.

**Costs.** Two dependencies, an API key of our own billed per scan, and a hard rule
that its output is displayed separately from rule-engine findings and never presented
as verified evidence. Also a real design constraint: at current scale one call with the
whole graph inlined would beat a fifteen-step tool loop on cost and latency. The loop
earns its place only when the account is too large to inline.

**Trigger.** Rule-engine findings stop surprising anyone, or an account gets big enough
that the graph does not fit in one prompt.

---

## 7. Scheduled syncs

**Idea.** Scan nightly instead of on a button press.

**Buys.** The findings table already records `first_seen_at` and `resolved_at`, so
history and trend lines come almost free once syncs happen on their own.

**Costs.** A scheduler, and with OAuth a refresh path that runs unattended — a token
that expires between manual scans is a nuisance, one that expires mid-schedule is a
silent gap.

**Trigger.** Anyone asks "is this getting better or worse?"

---

## 8. Local model, self-hosted

**Idea.** Run the assistant against a model inside our own environment rather than a
hosted API, so account inventory never leaves the network. Ollama serving an open
model to start; distillation onto a smaller task-specific model later.

**Why it matters more here than for most products.** The assistant sends resource
inventory to whichever provider serves it — droplet names, public IPs, VPC topology,
firewall rules, which databases are reachable. That is a map of how to attack the
account. A security vendor leaking it would be the whole business.

Today's posture is a proof of concept, not a production one: the key in use routes
through OpenRouter, so that data crosses two parties rather than one. Acceptable for a
sandbox account we created; not acceptable for a customer's.

**Costs.** Hosting and GPU capacity, and open models are generally weaker at
multi-step tool calling — which is the entire mechanic here, not a nice-to-have.

**The swap itself is small.** Every model reference goes through `agentModel()` in
`src/agent/model.ts`. Ollama is OpenAI-compatible, so this is the same shape as the
OpenRouter change already in that file:

```ts
createOpenAICompatible({ baseURL: "http://localhost:11434/v1" })("qwen2.5:32b")
```

**Do the cheap experiment first.** Distillation is a real programme — dataset,
training, evaluation, drift management. Before any of that, check whether a stock
open model already clears the bar: point `agentModel()` at Ollama, run the same
account, and compare against the hosted run. The measure is not prose quality, it is
whether it calls the right tools in the right order and stops when it should. If an
off-the-shelf model does that, distillation buys latency and cost, not capability —
and that is a much smaller argument for a much larger project.

**Trigger.** Any account we do not own. Before that, it is worth one afternoon of
measurement rather than a roadmap item.

---

## 9. Identity and entitlement analysis, IdP-paired

**Idea.** Add a *principal* to the graph — a team member, a token, a Spaces key, a
service account — with `can-access` edges to the resources its scope actually reaches.
The chain agent already traverses resource-to-resource edges; give it a principal as an
entry point and the same traversal produces a blast radius: *this intern's full-access
token reaches a `datastore`-sensitivity database it never otherwise touches*. Entitlement
is the one axis the engine is missing — it already computes sensitivity, exposure, and
reachability; who-can-touch-this is the fourth, and it is the one that names a person to
hold liable.

**Buys.** The Wiz-style contextual finding — not "this resource is exposed" but "this
identity can reach that sensitive resource by this path" — with the highest-liability
principal named. It reuses the existing engine rather than adding a second product: a
principal is just a new kind of entry point for a traversal that already exists.

**Why not a token checker first.** Considered and dropped as too rudimentary. Grading a
single pasted token in isolation has a remediation identical to the advice given at
connect time anyway (entry 1), and it produces no chain — just a label. The value is not
"this token is over-scoped", it is "*this* principal reaches *that* sensitive resource by
*this* path". That needs the principal in the graph, not a checker beside it.

**The data problem, and the honest fallback.** DigitalOcean's API cannot enumerate
tokens, their scopes, or team members' roles (see "Asked and answered", below), so the
principal set cannot be discovered from DO. Manual upload is the fallback — a member
list, a token inventory, a JSON of identity-to-grant — and it is consistent with how
Spaces buckets are already handled (`SPACES_BUCKETS`, entry 5): when the API cannot see
something, take explicit input rather than skip it silently.

**The real move: pair with an IdP.** Identity lives in the identity provider — Okta,
Entra ID, Google Workspace, JumpCloud — not in DigitalOcean. The IdP is the join key
that turns "a full-access token" into "*Bob's* token, and Bob is an intern who left last
month", which is the finding with liability attached. This is the CIEM pattern (cloud
entitlement correlated with directory identity) and it is where the role-based-escalation
story actually comes from; mechanism is SSO/SCIM directory sync. A CRM is **not** this —
it holds customers, not employees or grants — and is rejected explicitly so it is not
re-proposed.

*SCIM's limit, stated plainly.* SCIM supplies the *identities and groups* — who exists,
what team they are on — but it cannot map an **opaque DigitalOcean token to its owner or
its grants**: DO exposes no token introspection (see "Asked and answered"), so nothing
external can tell you which human minted a given PAT or what it can reach. The token↔owner
and token↔grant links remain a **manual mapping** the customer supplies; the IdP only
enriches the human side of a join the customer still has to make.

**Costs.** A principal node type and `can-access` edge in the schema and `derive.ts`, an
upload/ingest path, and — for the IdP phase — an OAuth app plus SCIM sync per provider,
with the per-provider quirks that implies. The chain agent and `report_findings` are
unchanged.

**Sequence.** Manual upload first: it tells the whole most-liable-identity story for a
demo and the first customers with no integration at all. IdP sync is the phase-2 scaling
layer, valuable only once the manual finding is shown to land. Skip the standalone token
checker entirely.

**Trigger.** A customer asks "who can reach our sensitive data, and should they", or
offboarding risk — a departed employee's credential still live — becomes the thing they
actually fear. IdP integration specifically: when manual upload proves the finding and
the bottleneck becomes keeping the principal set current by hand.

---

## 10. Memoized `ResourceGraph` for rules (tabled)

**Idea.** Replace the ad-hoc `ExposureContext` (one hand-built index) with a richer graph
object whose indices are memoized getters — `dropletsByTag`, `certificatesByLoadBalancer`,
`ownedIps`, `publicDropletIds`, and so on — so a cross-resource rule reads the index it
needs without recomputing anything and unused indices cost nothing.

**Buys.** Ergonomics for cross-resource rules, and one obvious home for the graph the 2d
visualization wants to render.

**Costs.** A new abstraction (`src/exposure/graph.ts`) that every rule signature then
depends on. The engine-hardening review judged it **not** foundational: the existing
explicit rule registry with a small evaluation context — indexed resources, collector
coverage, snapshot identity, `evaluatedAt` — is enough for the rules actually planned, and
a general graph adds indirection before there is a second consumer to justify it.

**Recommendation: table it.** Extending `ExposureContext` per-rule covers the near-term
detections. Revisit if the 2d graph (or several rule consumers) genuinely needs one shared
memoized structure — at which point the visualization layer and the rule engine reading the
*same* object is the argument for building it, not rule ergonomics alone.

**Trigger.** Two real consumers of the same graph — e.g. the attack-path rules **and** the
`/graph` page — both wanting memoized cross-resource indices that the per-rule evaluation
context cannot cheaply provide.

---

## Asked and answered: not possible

Recorded so they stop being re-proposed. Both were requested and neither is buildable
against DigitalOcean's API as it stands.

**Stale or over-scoped API tokens.** There is no `/v2/tokens` endpoint. Personal access
tokens cannot be enumerated, and neither can their scopes or last-used time. Token
sprawl is invisible to the API; the control panel is the only place it exists.

**Team members with excessive roles.** `/v2/organizations/teams` returns a team's
`member_count` and nothing else — no member list, no roles. The role enum appears only
in the invitation request body. "Who has admin on this account" cannot be answered.

Both would need DigitalOcean to ship new endpoints. Worth re-checking annually; worth
assuming no in the meantime. Entry 9 routes around both by sourcing identity from an IdP
or manual upload rather than from DigitalOcean — the API gap is why that entry exists.
