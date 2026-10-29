# Cloud and Deployment Classes (CLD-01 to CLD-12)

Use for IaC, container images, cloud configuration, serverless, ingress, and runtime settings. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## CLD-01: Identity and access management

- **Hunt:** Wildcard actions or resources, `*` principals, admin roles on application identities, shared service accounts across services or environments, long-lived access keys, missing conditions, role assumption without external id or subject restrictions, user-assignable privileged roles.
- **Confirms:** Compromise of one workload yields broader access than its function needs, and the path is reachable (for example through an SSRF or RCE finding).
- **Not a finding:** Narrow resource-scoped permissions with managed or federated identity.

## CLD-02: Network exposure

- **Hunt:** `0.0.0.0/0` on databases, caches (Redis, Memcached), Elasticsearch, MongoDB, SSH, RDP, Kubernetes API, message brokers, admin panels, public IPs on private services, "allow Azure services" firewall shortcuts, origins reachable directly behind a CDN or WAF.
- **Confirms:** A data store or admin surface is reachable from the internet with weak or no authentication, or an edge control can be bypassed by hitting the origin.
- **Not a finding:** Private networking or allowlisted sources plus strong authentication.

## CLD-03: Object storage and data-at-rest exposure

- **Hunt:** Public buckets and containers, public ACLs, listing enabled, shared-key access, long-lived or broad SAS and pre-signed URLs, unencrypted volumes and snapshots, public snapshots or images, missing soft delete and versioning on critical data.
- **Confirms:** Sensitive objects are readable or writable without authorization.
- **Not a finding:** Intentionally public static assets in a separate bucket.

## CLD-04: Metadata services and workload identity theft

- **Hunt:** IMDSv1 enabled, link-local access from application containers, `hop limit` too high, Azure and GCP metadata reachable without header controls, workload tokens exposed to app code that fetches arbitrary URLs, forwarded request headers reaching metadata endpoints.
- **Confirms:** A reachable SSRF can retrieve cloud credentials.
- **Not a finding:** IMDSv2 required with hop limit 1, fetchers blocked from link-local ranges.

## CLD-05: Container and Kubernetes configuration

- **Hunt:** Root user, privileged containers, host path or Docker socket mounts, added capabilities, writable root filesystems, `latest` tags, secrets in image layers or env of images, default service account tokens mounted, wildcard RBAC, no NetworkPolicy, exposed dashboards or kubelet, no admission policy, secrets not encrypted at rest.
- **Confirms:** Container escape or lateral movement is feasible from a plausible compromise.
- **Not a finding:** Non-root, read-only filesystem, dropped capabilities, pinned digests.

## CLD-06: Secrets and configuration management

- **Hunt:** Secrets in IaC, environment files, container args, image history, build logs, repository settings visible to many users, same secret across environments, no rotation, secrets in app settings without a vault, vault access policies too broad, deploy hooks as bearer URLs.
- **Confirms:** A secret is readable by identities that should not have it, or shared across trust levels (production secret in preview).
- **Not a finding:** Vault-backed references, per-environment secrets, rotation procedure.

## CLD-07: Serverless and edge functions

- **Hunt:** Anonymous HTTP triggers meant to be private, function keys used as user auth, overly broad execution roles, no concurrency or spend limits, module-scope state shared across concurrent requests or invocations (cross-request data leaks), unbounded retries causing duplicate effects, secrets in function config visible in portals.
- **Confirms:** Unauthorized invocation, cross-request data leakage, or unbounded cost.
- **Not a finding:** Authenticated triggers, per-request state, quotas set.

## CLD-08: Ingress, TLS, and WAF

- **Hunt:** WAF in detection-only mode, missing rate limits at the edge, TLS termination gaps, origin lock-down missing, default certificates, host-based routing that allows unknown hosts, request size and timeout limits absent, preview or staging hosts publicly routable.
- **Confirms:** An attack the edge is meant to stop reaches the application, or internal environments are internet-visible with real data.
- **Not a finding:** Prevention mode with origin lock and tested rules.

## CLD-09: Databases and managed data services

- **Hunt:** Public endpoints, shared superuser for application runtime, no TLS enforcement, no per-service roles, disabled auditing, backups unencrypted or never restored in testing, preview or dev branches copied from production with personal data, connection strings used from client code.
- **Confirms:** The runtime role can read or alter more than needed, or production data lives in lower-trust environments.
- **Not a finding:** Least-privilege roles, TLS required, tested restores, anonymized non-production data.

## CLD-10: Environment separation

- **Hunt:** Production credentials in preview, staging, or CI, shared databases, shared queues or buckets, same signing keys, debug flags, test payment keys mixed with live keys, feature flags that differ silently, public preview URLs that expose staging data.
- **Confirms:** Compromise or misuse of a lower environment affects production, or lower environments expose real data.
- **Not a finding:** Isolated accounts or subscriptions and separate secrets.

## CLD-11: Logging, monitoring, and alerting (OWASP A09)

- **Hunt:** No audit trail for auth events, privilege changes, payment changes, secret access, or admin actions; logs containing passwords, tokens, card data, or full personal data; mutable log storage; no alerts on signature failures, repeated auth failures, unusual spend; retention absent; log injection through unescaped user data.
- **Confirms:** An attack would go undetected or logs themselves leak sensitive data.
- **Not a finding:** Structured, redacted, alerting logs with tamper-resistant storage.

## CLD-12: Backup, restore, and recovery

- **Hunt:** No backups, backups in the same failure domain, untested restores, deletion protection missing, no documented recovery objectives, secrets needed for recovery stored only in the system being recovered, migration rollback absent.
- **Confirms:** A realistic failure or attack would cause irrecoverable loss.
- **Not a finding:** Tested restore with documented time and point objectives.
