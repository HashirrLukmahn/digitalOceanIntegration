# Design notes

Tradeoffs, incomplete collectors, and what I would do next.

---

## What DigitalOcean does and does not expose

Every field this app reads was taken from DigitalOcean's
[public OpenAPI specification](https://github.com/digitalocean/openapi) rather than
from memory, because a wrong guess about a field name produces a confidently wrong
finding. Four things that came out of that and shaped the build:

**`ports` is a string, and `"0"` means every port.** Not port zero. Reading it
literally turns "everything is open to the internet" into the far less alarming
"port 0 is open", which is exactly backwards. There is a test for it.

**Firewalls attach by tag as well as by id.** Resolving only `droplet_ids` would
report correctly firewalled droplets as unprotected — a false positive that teaches
people to ignore the tool. The fixture set includes a tag-attached firewall for this
reason.

**The DOKS control-plane firewall is nullable and invite-only.** `null` means "this
account cannot tell us", not "unrestricted". Treating null as unrestricted would raise
a finding on essentially every cluster in existence, so the rule fires only when
DigitalOcean states the control plane is open.

**Database trusted sources have no VPC type.** Trust is expressed per droplet, tag,
k8s cluster, app, or IP. So this app never claims a database "trusts the whole VPC" —
the API cannot express it and the claim would be unfalsifiable.

---

## Incomplete collectors

### Spaces — the significant one

The v2 API exposes only `/v2/spaces/keys`. There is **no bucket-listing endpoint and
no bucket-ACL endpoint** — those live in the S3-compatible API, which authenticates
with a Spaces access key pair rather than a personal access token. Minting such a key
requires `spaces_key:create`, a write scope a read-only tool should not request.

This is not a limitation I worked around; it is the shape of the platform:

| Tool | DigitalOcean | Spaces |
|---|---|---|
| Wiz | not supported | — |
| Prowler | not supported ([open request](https://github.com/prowler-cloud/prowler/issues/8269)) | — |
| Steampipe | 24 tables | **omitted entirely** |
| CloudQuery | supported | supported, via a **second credential** |
| Terraform / Pulumi | supported | supported, via a **second credential** |

Steampipe has 24 DigitalOcean tables and no Spaces table at all. CloudQuery covers
Spaces but requires `spaces_access_key_id` / `spaces_secret_access_key` alongside the
API token. Nobody does it with one credential, because it cannot be done.

**What this app does instead.** Two observations separate the problem:

1. Detecting whether a *named* bucket is public needs no credential. An unauthenticated
   request that succeeds is proof by demonstration, which is stronger evidence than
   reading a configuration field — and it is the only rule here whose evidence is a
   demonstration rather than an inference.
2. A credential is needed only to *enumerate* buckets, and DigitalOcean appears to gate
   listing behind full access, which also grants delete.

So the bucket list comes from configuration, detection is anonymous, and the optional
key pair exists to be **checked** rather than used: a key with account-wide or write
access is refused outright. A security tool that declines a credential more powerful
than it needs is worth more than one that asks politely and accepts whatever arrives.

**The cost, stated plainly:** a customer must name their buckets, so the app can only
audit buckets they remembered. The forgotten staging bucket — the one these findings
usually turn out to be about — stays invisible. That is a real limitation, and the
coverage report says so rather than implying complete coverage.

**Unresolved:** whether `{"bucket": "", "permission": "read"}` is accepted when
creating a key. The spec documents empty-bucket for `fullaccess` and documents `read`
as a permission, but never the combination. If it works, enumeration without mutation
becomes possible and this whole tradeoff dissolves. It needs one live API call to
settle and I did not have an account to settle it with.

### Permanent blind spots

**API tokens.** There is no `/v2/tokens` endpoint — I checked all 445 paths in the
spec. Personal access tokens, their scopes, and their last-used dates cannot be
enumerated. Token sprawl is unauditable via API.

**Team members and roles.** `/v2/organizations/teams` returns a `member_count` and
nothing else. No member list, no roles. "Who has admin on this account" is
unanswerable, which is why this app derives no access or privilege-escalation
relationships from team membership.

---

## Decisions worth explaining

### Reconciliation is scoped per resource type

`removed_at` and `resolved_at` mean "absent from a later authoritative sync", and
absence is only evidence of deletion if that resource type was successfully listed. So
droplets are reconciled when the droplets collector succeeded, whatever else failed.

Gating reconciliation on a fully clean run looks simpler and is wrong twice: one flaky
optional collector would freeze deletion tracking for the entire inventory, and since
the Spaces collector can never succeed, no run would ever qualify. Two tests pin this,
including "a failed droplets collector must not mark every droplet deleted."

### Severity is calibrated

The temptation is to score every public endpoint `critical`, which produces a report
nobody reads twice. Severity is sensitivity × reachability: a public HTTPS load
balancer is `low`, a database open to `0.0.0.0/0` is `critical`, and the same droplet
rule yields `high` for open SSH and `low` for open 443.

The interface reinforces this — `low` is rendered in neutral grey rather than a
caution colour, because a public web service is a fact worth recording, not a warning.

### One finding per actionable exposure

A droplet with five world-open firewall rules is one problem to fix, not five rows.
Each contributing rule is listed in the evidence so the reviewer sees exactly what to
change. The fingerprint covers the sorted set of offending rules, so fixing one
resolves the finding and raises a new one describing what remains.

### Findings are not all reachability findings

`app.plaintext_secret_env` is a disclosure problem, not a reachability one, so it does
**not** set `is_internet_exposed`. Letting a secrets-hygiene issue mark an app as
internet-facing would corrupt the meaning of that column. Findings carry
`provesInternetExposure` for this.

### Unknown never looks like safe

A dashed border in the interface means "not assessed". Findings pages carry the
coverage panel, which ends: *"An absent finding is not evidence of a safe
configuration for anything listed here."* Silent truncation is the failure mode that
would matter most in this product, so pagination throws on hitting its page cap rather
than returning a short list that looks complete.

---

## Next steps

1. **Settle the read-all Spaces key question.** One API call. It determines whether
   bucket enumeration is possible without holding delete rights.
2. **OAuth instead of a pasted token**, for a multi-tenant version. With a personal
   access token the customer chooses the scopes, and the control panel's easy path is
   Full Access; with OAuth the application specifies the scopes and the customer
   cannot over-grant. For a read-only security tool that is close to decisive.
3. **Certificates.** `/v2/certificates` is already reachable with the current scopes
   and expiry is a cheap, real finding.
4. **Finding history.** Rows already carry `first_seen_at` / `resolved_at`; the
   interface shows only current state. A trend view is mostly presentation work.
5. **Scheduled syncs.** Everything is idempotent and the reconciliation semantics are
   settled, so this is a scheduler and a lock rather than new logic.

## Things I would change with more time

- The Spaces probe is sequential. Fine for a handful of named buckets, slow for fifty.
- `listFindings` filters by resource type in application code rather than in SQL,
  which is a per-row lookup. Correct, but it should be a join.
- No pagination in the inventory table. At a few hundred resources it is fine; at ten
  thousand it is not.
