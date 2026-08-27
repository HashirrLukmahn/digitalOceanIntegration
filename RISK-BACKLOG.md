# Intricate risk backlog

The single-resource rules are the floor. This is the roadmap of *intricate* risks — mostly
cross-resource paths and DigitalOcean-specific misconfigurations — with the API signal each
needs and the rule shape. DO has no IAM or service accounts, so the leverage is in
**relationships**: what a public resource can reach through the graph.

Priority is value × how cleanly the API supports it (a rule we cannot detect without
guessing does not ship — it becomes a declared blind spot instead).

## Shipped (for reference)

- `path.public_workload_to_datastore` — internet-exposed workload a datastore *trusts*.
- `path.exposed_app_leaks_datastore_credential` — public App Platform app holding a
  datastore credential in plaintext.
- `load_balancer.sensitive_backend_port` — public LB → sensitive backend port the backend
  firewall admits (effective allow-minus-deny).

## P1 — cross-resource paths (highest leverage)

1. **`path.public_lb_to_trusted_datastore` (multi-hop).** Chain the two we have: a public
   load balancer → backend droplet → a datastore that *trusts* that droplet. Needs the
   path engine to walk two edges (`routes_to` then `trusts`) instead of one. Signal:
   already collected (LB backends, firewalls, DB trusted sources). This is the flagship
   "three things each fine, together a breach" case.

2. **`path.exposed_workload_to_attached_datastore`.** A public droplet with an
   `attached_to` volume. The volume is `datastore` sensitivity, so compromising the public
   droplet reaches data at rest — even though the volume is never itself exposed. Signal:
   the `attached_to` edge we already derive + `exposedResourceIds`. Clean and high value.

3. **`path.public_kubernetes_to_trusted_datastore`.** A cluster whose control plane is open
   (`kubernetes.public_control_plane` finding) and whose workloads a database trusts (the
   `k8s` trusted-source form, already an edge). Reuses the existing path machinery.

## P2 — DO-specific single-resource rules (clean API signal)

4. **`load_balancer.weak_tls_policy`.** LB `tls_cipher_policy` set to a weak/legacy policy
   on a public HTTPS frontend. Provider-reported field; low-to-medium.

5. **`firewall.broad_private_ingress_to_sensitive_port`.** Now detectable because the
   effective-policy evaluator exists: a firewall allowing a *sensitive* port (SSH, DB…)
   from a broad private CIDR (e.g. `10.0.0.0/8`) — lateral-movement surface inside the VPC.
   Context/medium, not internet-exposure. [effective-policy.ts]

6. **`app.wildcard_cors_with_credentials`.** App CORS allowing a literal `*` (or reflected
   origin) together with credentials. The plan calls for splitting the literal wildcard
   from broad regex and verifying provider behavior before assigning severity.

7. **`registry.mutable_or_public_image`.** Container-registry supply-chain risk: use of the
   `latest` tag or a publicly readable registry that DOKS pulls from — a bad push is pulled
   on next deploy. Needs the registry/repository API; verify field availability first.
   Source: DO Kubernetes security best practices.

## P3 — lower value or needs verification

8. **`space.public_bucket_serving_app`.** A public-listable Spaces bucket that is an app/CDN
   origin (cross-link a `space.public_read` finding to an app that references it). Extends a
   finding we already have.

9. **`kubernetes.public_workers`.** Blocked: the `isolated_workers` field's semantics are
   ambiguous (dedicated-hardware vs networking). Ship only once the OpenAPI `description`
   confirms it is about worker networking. Do not invent the meaning.

## Declared blind spots (document, do not rule)

The API cannot support these without guessing, so they stay honest gaps, surfaced in the
manual-controls section rather than as findings:

- **Droplet metadata SSRF** (`169.254.169.254`, may serve `user_data` secrets) — cannot
  test reachability, and `user_data` is deliberately never read.
- **In-cluster CVEs** (IngressNightmare-class) — needs an authorized in-cluster read.
- **SSH posture** (root login, password auth) — not exposed by the API.
- **Snapshot / image sharing** — `image.public_shared` deprioritized as a provider-contract
  anomaly rather than an exposure.
- **Token scope / rotation and team-role sprawl** — no `/v2/tokens`, teams API returns only
  `member_count`. These are the fourth axis (entitlement) that only an IdP integration can
  supply (see `IDEAS.md` entry 9).

## Sources

- [DO Droplet security best practices](https://www.digitalocean.com/security/security-best-practices-guide-droplet)
- [DO Spaces security best practices](https://www.digitalocean.com/security/security-best-practices-guide-spaces)
- [DO Kubernetes best practices — security](https://www.digitalocean.com/blog/digitalocean-kubernetes-best-practices-security)
- [Managing cloud security posture on DigitalOcean](https://www.digitalocean.com/blog/managing-cloud-security-on-digitalocean)
