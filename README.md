# DigitalOcean exposure review

Connects to a DigitalOcean team with a read-only token, inventories its resources,
and identifies what is reachable from the internet — with the provider value that
proves it attached to every finding.

Runs entirely locally: SQLite, one migration command, no external infrastructure.

---

## Quick start

Nothing here needs a DigitalOcean account. Fixture mode runs the whole pipeline —
collectors, pagination, normalization, every rule — against recorded payloads.

```bash
npm install
cp .env.example .env
npm run db:migrate
npm run dev
```

Open <http://localhost:3000>, go to **Connection**, and press **Sync now**.

### With a real account

Create a read-only personal access token in the DigitalOcean control panel
(**API → Tokens → Generate New Token**, with **Read Only** selected — the `api:read`
scope), then in `.env`:

```
DATA_SOURCE=live
DIGITALOCEAN_TOKEN=dop_v1_...
```

The token is read from the environment at the moment of use. It is never written to
the database, the logs, or the export.

---

## The demo flow

1. **Connection** — shows which credential is configured and what it can reach.
   *Test connection* resolves the team; *Sync now* runs a full inventory.
2. **Inventory** — every resource, internet-facing first. Filter by type, region,
   sensitivity, exposure, or search text. Click any identifier for detail.
3. **Exposures** — findings ordered by severity. Open one to see the exact firewall
   rule, trusted source, or HTTP response that proves the exposure.
4. **Syncs** — every run, including partial ones, with per-collector coverage.
5. **Export JSON** — the normalized inventory, relationships, findings, and coverage.

---

## Commands

```bash
npm run dev          # start the app
npm run build        # production build
npm run db:migrate   # apply checked-in migrations
npm run db:generate  # new migration after a schema change
npm test             # 193 tests
npm run typecheck    # tsc --noEmit
```

---

## Architecture

Collectors, normalization, relationships, and rules are all plain functions with no
Express or Next types in them, so every one is testable without booting the app.

```
src/
  do/         collectors, pagination, HTTP transport, fixtures, Spaces
  normalize/  provider objects -> the normalized contract; metadata allowlist
  relationships/  provider-reported and derived edges
  exposure/   rules (one per file), severity calibration, fingerprinting
  sync/       orchestration, coverage, reconciliation
  export/     the JSON export
  data/       read helpers for the pages
app/          Next App Router pages and API routes
```

Data flows one way: **collect raw → normalize → relate → evaluate → persist**.

Collectors keep the provider's objects at full fidelity, because a firewall rule's
exact source and port range *is* the evidence for a finding. The database stores a
narrower, allowlisted projection. Collapsing those two steps would mean either storing
more than we should or reasoning about exposure with less than we have.

### Filters

Filtering is server-rendered from URL query parameters, so any view is a shareable
link and the back button works. There is no client-side table state.

---

## Exposure rules

All findings are deterministic. No language model decides whether a finding exists.

| Rule | Fires when |
|---|---|
| `droplet.no_firewall` | Public IP and no firewall attached — by id **or** by tag |
| `droplet.public_ingress` | Public IP and a firewall rule admitting `0.0.0.0/0` or `::/0` |
| `load_balancer.public_frontend` | `network: EXTERNAL`, or a public IP if the field is absent |
| `database.public_no_trusted_sources` | Public endpoint and an empty trusted-source list |
| `database.trusted_source_is_public` | A trusted source of `0.0.0.0/0` or `::/0` |
| `kubernetes.public_control_plane` | Control-plane firewall disabled, or its allowlist admits everything |
| `app.public_ingress` | A public App Platform URL |
| `app.plaintext_secret_env` | A credential-shaped variable name left at the plaintext `GENERAL` default |
| `space.public_read` | An unauthenticated request successfully listed the bucket |

**Severity is calibrated, not maximal.** A public HTTPS load balancer is `low` — that
is what a load balancer is for. A managed database reachable from `0.0.0.0/0` is
`critical`. The same rule produces `high` for a droplet with SSH open to the world and
`low` for one with only 443 open. Severity comes from sensitivity × reachability, in
`src/exposure/severity.ts`.

---

## Secret handling

- **The token is never persisted.** Read from the environment per call; the
  Connection page shows a `****abcd` fingerprint and nothing more. There is no field
  to paste a token into, because a form that accepts a secret and then discards it is
  a confusing promise.
- **Metadata is allowlisted, not denylisted.** `metadata_json` is built by copying
  permitted keys, so a field DigitalOcean adds in future is invisible by default
  rather than exposed by default. A denylist backs it up as a second line.
- **Logs and stored errors are scrubbed by value**, not only by key name, so a token
  quoted inside a dependency's error message is still caught.
- Tests assert that fixture passwords, connection URIs, and API keys appear nowhere in
  the database or the export.

The App Platform collector is the reason this matters in practice: `/v2/apps` returns
`GENERAL` environment variables in **plaintext**, so syncing apps pulls third-party
credentials into memory without calling anything that looks dangerous. The allowlist
never copies `spec`.

---

## Object storage (optional, off by default)

DigitalOcean's v2 API cannot list Spaces buckets or read their permissions, so buckets
are named explicitly rather than discovered:

```
SPACES_BUCKETS=nyc3/assets,ams3/backups
```

Public-read detection needs **no credential** — it is an unauthenticated request, and
a successful one is proof by demonstration rather than inference from a config field.

If you also supply `SPACES_ACCESS_KEY_ID` / `SPACES_SECRET_ACCESS_KEY`, the key's
grants are checked before use and a key with account-wide or write access is
**refused**, not merely warned about.

See [DESIGN-NOTES.md](DESIGN-NOTES.md) for why this is the shape it is.

---

## Tests

193 tests, no network access required.

| Area | Covers |
|---|---|
| `pagination` | Multi-page follow, cycle guard, refusal to truncate silently |
| `normalization` | Identifier formats, sensitivity, tags, null handling |
| `sanitization` | Allowlist is default-deny; credentials never survive |
| `exposure` | All rules, both directions, plus the `ports: "0"` trap |
| `app-secrets` | Name detection; values never read |
| `spaces` | Config parsing, least-privilege refusals, probe semantics |
| `sync` | End-to-end against SQLite, reconciliation, partial runs |
| `export` | The contract shape, field by field |

Tests run the checked-in migrations rather than pushing the schema, so a migration
that drifts from the schema fails the suite.

---

## Known gaps

Summarised in [DESIGN-NOTES.md](DESIGN-NOTES.md). The short version: Spaces buckets
cannot be enumerated with a read-only token, and API tokens and team member roles have
no API at all — those are permanent blind spots, stated rather than worked around.

## Ideas and deferred features

Features considered and not shipped, with tradeoffs and what would trigger building
each: [IDEAS.md](IDEAS.md).
