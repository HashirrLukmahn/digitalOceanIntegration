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

**Unverified.** Whether OAuth can request the granular `droplet:read` style scopes or
only the `api:read` alias. The OAuth reference links to the full granular list, which
implies the former, but never states it. One authorize URL in a browser settles it.

**Trigger.** The first customer who is not us.

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
assuming no in the meantime.
