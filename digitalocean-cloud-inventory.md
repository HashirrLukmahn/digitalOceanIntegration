# DigitalOcean Cloud Security Work Trial

## Deliverable

Build a standalone web app that connects to a DigitalOcean team, inventories
its resources, identifies internet exposure, and explains the supporting
evidence. The app must run locally without access to Parameter's source code,
database, APIs, or infrastructure.

The submission is a separate repository containing the application, schema,
setup instructions, tests, and a short design note.

## Required demo flow

1. Start the app locally.
2. Enter a read-only DigitalOcean token.
3. Sync the connected team's resources.
4. Browse and filter the inventory.
5. Open an exposure finding and see why the resource is considered public.
6. Export the normalized inventory and findings as JSON.

## Suggested stack

Use the stack that produces the strongest result in three days. The smallest
reasonable default is:

- TypeScript
- Next.js or another full-stack web framework
- SQLite with Drizzle ORM or Prisma
- A simple component library
- DigitalOcean REST API

SQLite is sufficient. The evaluator should be able to clone the repository,
install dependencies, run one migration command, and start the app without
provisioning external infrastructure.

## Authentication

The app accepts a DigitalOcean personal access token with the read-only
`api:read` scope. Store it in an environment variable for the three-day demo;
do not persist it in SQLite, logs, browser storage, or exported JSON.

If the app supports multiple saved connections, encrypt tokens before storage
using a key supplied through an environment variable. This is optional and
should not displace inventory or exposure work.

References:

- [DigitalOcean personal access tokens](https://docs.digitalocean.com/reference/api/create-personal-access-token/)
- [DigitalOcean API token scopes](https://docs.digitalocean.com/reference/api/scopes/)

## Local database schema

The app should create these tables locally through checked-in migrations.

### `cloud_accounts`

One row for the connected DigitalOcean team.

| Column           | Type               | Rule                                   |
| ---------------- | ------------------ | -------------------------------------- |
| `id`             | text               | App-generated primary key              |
| `provider`       | text               | Always `digitalocean`                  |
| `external_id`    | text               | Stable DigitalOcean team identifier    |
| `name`           | text               | Team display name                      |
| `last_synced_at` | timestamp nullable | Most recent successful or partial sync |
| `created_at`     | timestamp          | Creation time                          |
| `updated_at`     | timestamp          | Last update time                       |

Unique: `(provider, external_id)`.

### `sync_runs`

One row for each attempted inventory sync.

| Column                | Type               | Rule                                           |
| --------------------- | ------------------ | ---------------------------------------------- |
| `id`                  | text               | Primary key                                    |
| `account_id`          | text               | Foreign key to `cloud_accounts`                |
| `status`              | text               | `running`, `completed`, `partial`, or `failed` |
| `resources_count`     | integer            | Persisted resources                            |
| `relationships_count` | integer            | Persisted relationships                        |
| `findings_count`      | integer            | Derived exposure findings                      |
| `coverage_json`       | JSON               | Completed and failed collectors                |
| `error`               | text nullable      | Sanitized terminal error                       |
| `started_at`          | timestamp          | Start time                                     |
| `completed_at`        | timestamp nullable | Terminal time                                  |

### `cloud_resources`

One row per current DigitalOcean resource.

| Column                | Type               | Rule                                        |
| --------------------- | ------------------ | ------------------------------------------- |
| `id`                  | text               | App-generated primary key                   |
| `account_id`          | text               | Foreign key to `cloud_accounts`             |
| `external_id`         | text               | Stable `do:<type>:<provider-id>` identifier |
| `resource_type`       | text               | Normalized resource type                    |
| `name`                | text               | Human-readable name                         |
| `region`              | text nullable      | DigitalOcean region slug                    |
| `state`               | text nullable      | Provider lifecycle state                    |
| `is_internet_exposed` | boolean            | Deterministic exposure result               |
| `sensitivity`         | text               | `none`, `credential`, or `datastore`        |
| `tags_json`           | JSON               | DigitalOcean tags                           |
| `metadata_json`       | JSON               | Allowlisted provider metadata only          |
| `first_seen_at`       | timestamp          | First observed time                         |
| `last_seen_at`        | timestamp          | Latest observed time                        |
| `removed_at`          | timestamp nullable | Set when absent from a later complete sync  |

Unique: `(account_id, external_id)`.

### `cloud_relationships`

Provider-reported or deterministically derived resource relationships.

| Column               | Type | Rule                                                    |
| -------------------- | ---- | ------------------------------------------------------- |
| `id`                 | text | Primary key                                             |
| `account_id`         | text | Foreign key to `cloud_accounts`                         |
| `source_external_id` | text | Source resource identifier                              |
| `target_external_id` | text | Target resource identifier                              |
| `relationship`       | text | `contains`, `attached_to`, `routes_to`, or `depends_on` |
| `evidence`           | text | `provider_reported` or `derived`                        |
| `metadata_json`      | JSON | Evidence needed to explain the edge                     |

Unique: `(account_id, source_external_id, target_external_id, relationship)`.

### `exposure_findings`

One row per actionable exposure, not one row per raw firewall rule.

| Column                 | Type               | Rule                                                        |
| ---------------------- | ------------------ | ----------------------------------------------------------- |
| `id`                   | text               | Stable fingerprint primary key                              |
| `account_id`           | text               | Foreign key to `cloud_accounts`                             |
| `resource_external_id` | text               | Exposed resource                                            |
| `kind`                 | text               | Stable exposure category                                    |
| `severity`             | text               | `low`, `medium`, `high`, or `critical`                      |
| `title`                | text               | Short finding title                                         |
| `summary`              | text               | What is exposed and why it matters                          |
| `evidence_json`        | JSON               | Public IP, rule, port, or provider setting proving exposure |
| `remediation`          | text               | Specific corrective action                                  |
| `first_seen_at`        | timestamp          | First observation                                           |
| `last_seen_at`         | timestamp          | Latest observation                                          |
| `resolved_at`          | timestamp nullable | Set when absent from a later complete sync                  |

Fingerprint input: account, resource external ID, finding kind, and the stable
configuration element that must be changed.

## Normalized resource contract

The database and JSON export use the same resource shape:

```typescript
interface CloudResource {
  provider: "digitalocean";
  externalId: string;
  resourceType: string;
  name: string;
  region: string | null;
  state: string | null;
  isInternetExposed: boolean;
  sensitivity: "none" | "credential" | "datastore";
  tags: Record<string, string>;
  metadata: Record<string, unknown>;
}
```

| Resource           | `resourceType`                    | `externalId`           | Sensitivity  |
| ------------------ | --------------------------------- | ---------------------- | ------------ |
| Project            | `digitalocean.project`            | `do:project:<id>`      | `none`       |
| Droplet            | `digitalocean.droplet`            | `do:droplet:<id>`      | `none`       |
| Firewall           | `digitalocean.firewall`           | `do:firewall:<id>`     | `none`       |
| Load balancer      | `digitalocean.load_balancer`      | `do:loadbalancer:<id>` | `none`       |
| VPC                | `digitalocean.vpc`                | `do:vpc:<id>`          | `none`       |
| Kubernetes cluster | `digitalocean.kubernetes_cluster` | `do:kubernetes:<id>`   | `credential` |
| Managed database   | `digitalocean.database_cluster`   | `do:dbaas:<id>`        | `datastore`  |
| Space              | `digitalocean.space`              | `do:space:<name>`      | `datastore`  |
| App Platform app   | `digitalocean.app`                | `do:app:<id>`          | `none`       |
| Container registry | `digitalocean.container_registry` | `do:registry:<name>`   | `credential` |
| Volume             | `digitalocean.volume`             | `do:volume:<id>`       | `datastore`  |

Allowlisted metadata may include project ID, VPC ID, public/private addresses,
firewall IDs, backend IDs, database engine/version, and public hostname. It must
exclude tokens, credentials, connection strings, user data, certificates,
database users, Kubernetes credentials, registry credentials, and object data.

## Required collectors

Minimum viable inventory:

- Projects and project resources
- Droplets
- Cloud firewalls
- Load balancers
- VPCs
- Managed databases

Strong submission:

- Kubernetes clusters
- App Platform apps
- Spaces
- Container registries
- Volumes

Every list endpoint must follow pagination. A failed optional collector produces
a partial sync with visible coverage rather than discarding successful data.

DigitalOcean exposes project membership as resource URNs through
`GET /v2/projects/{project_id}/resources`.

Reference: [DigitalOcean project resources](https://docs.digitalocean.com/products/projects/reference/api/project-resources/)

## Relationships

| Source        | Relationship  | Target                                      |
| ------------- | ------------- | ------------------------------------------- |
| Project       | `contains`    | Project resource                            |
| Firewall      | `attached_to` | Droplet                                     |
| Droplet       | `attached_to` | VPC                                         |
| Load balancer | `routes_to`   | Droplet                                     |
| Volume        | `attached_to` | Droplet                                     |
| App           | `depends_on`  | Database, only when provider data proves it |

Do not infer access or privilege-escalation relationships from DigitalOcean team
membership. A missing relationship is better than an unsupported security
claim.

## Exposure rules

All findings are deterministic. An LLM may explain a finding as a stretch goal,
but it cannot decide whether the finding exists.

| Resource           | Exposure condition                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Droplet            | Public IP plus no attached firewall, or an inbound firewall rule admitting `0.0.0.0/0` or `::/0` to at least one port |
| Load balancer      | Public frontend address                                                                                               |
| Managed database   | Public access with no trusted-source restriction, or a trusted source admitting the public internet                   |
| Kubernetes cluster | Public control-plane endpoint whose allowlist admits the public internet                                              |
| Space              | Anonymous listing or object reads enabled                                                                             |
| App Platform app   | Public ingress URL                                                                                                    |

Do not mark every resource with a public IP vulnerable. Record the reachable
ports and the rule or provider setting that proves reachability. A public web
service on port 443 may be intentional; the app should still record exposure
but calibrate severity from sensitivity and reachability rather than labeling
every public endpoint critical.

## Web app pages

### `/connections`

- Enter or rotate the DigitalOcean read-only token.
- Test the connection.
- Start a sync and show its status and coverage.

### `/inventory`

- Show resource type, name, region, state, exposure, and sensitivity.
- Filter by resource type, region, exposure, sensitivity, and search text.
- Open a resource detail page with allowlisted metadata and relationships.

### `/exposures`

- Sort findings by severity.
- Filter by kind and resource type.
- Show evidence, affected resource, and remediation.
- Never show an LLM-only claim as verified evidence.

### `/syncs`

- Show completed, partial, and failed runs.
- Show collector-level coverage and sanitized errors.

## JSON export

The evaluator-facing integration boundary is a downloaded JSON file:

```typescript
interface DigitalOceanSecurityExport {
  schemaVersion: "1";
  generatedAt: string;
  account: {
    provider: "digitalocean";
    externalId: string;
    name: string;
  };
  resources: CloudResource[];
  relationships: Array<{
    sourceExternalId: string;
    targetExternalId: string;
    relationship: "contains" | "attached_to" | "routes_to" | "depends_on";
    evidence: "provider_reported" | "derived";
    metadata: Record<string, unknown>;
  }>;
  findings: Array<{
    fingerprint: string;
    resourceExternalId: string;
    kind: string;
    severity: "low" | "medium" | "high" | "critical";
    title: string;
    summary: string;
    evidence: Record<string, unknown>;
    remediation: string;
  }>;
  coverage: {
    completedCollectors: string[];
    failedCollectors: Array<{ collector: string; message: string }>;
  };
}
```

This export is the only compatibility requirement. Hashirr does not need access
to Parameter's schema or web application.

## Submission requirements

- Separate repository owned by Hashirr or shared with the evaluators
- README with setup, migration, run, test, and architecture instructions
- Checked-in local database migrations
- `.env.example` with no live secrets
- Seed or mocked fixture mode so the UI can be evaluated without a live token
- Tests for pagination, normalization, metadata sanitization, and at least three
  exposure rules
- A short note covering tradeoffs, incomplete collectors, and next steps

## Evaluation rubric

| Area                                | Weight |
| ----------------------------------- | -----: |
| Correct inventory and pagination    |    25% |
| Evidence-backed exposure logic      |    25% |
| Security and secret handling        |    20% |
| Usable web app                      |    15% |
| Schema, tests, and code quality     |    10% |
| Documentation and tradeoff judgment |     5% |

## Out of scope

- Access to Parameter's repository, database, internal APIs, or deployment
- Active exploitation or mutation of DigitalOcean resources
- Production hosting
- Multi-tenant authentication
- Billing management
- A generalized multi-cloud framework
- LLM-generated security claims without deterministic evidence
