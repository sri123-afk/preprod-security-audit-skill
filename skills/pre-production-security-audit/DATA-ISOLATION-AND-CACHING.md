# Data Isolation, Caching, and Lifecycle Classes (DATA-01 to DATA-10)

Use for multi-tenant data, caches, CDNs, search, exports, background jobs, backups, migrations, and deletion. Cache and isolation bugs are often small, silent, and severe. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## DATA-01: Tenant and owner scoping in every query

- **Hunt:** Queries, joins, aggregates, and bulk updates lacking `tenant_id` or owner predicates; ORM scopes bypassed by raw SQL or `IgnoreQueryFilters`; admin tools using the same code path as tenants; background jobs that load by id without tenant context; soft-delete filters missing in joins; uniqueness constraints that ignore tenant.
- **Confirms:** A principal in tenant A can read, change, or collide with tenant B data. Name both tenants and the request.
- **Not a finding:** Mandatory scoping helper, enforced row-level security for the runtime role, tests proving cross-tenant denial.

## DATA-02: Row-level security correctness

- **Hunt:** RLS not enabled or not forced for table owners, runtime role that owns tables or has `BYPASSRLS`, policies missing `WITH CHECK`, tenant context set with session-level `SET` on pooled connections (leaks across clients in transaction pooling), context taken from client-controlled headers, views and functions running as definer that bypass policies, missing policy for `INSERT` and `UPDATE`.
- **Confirms:** A request can see or write rows outside its tenant through the runtime connection.
- **Not a finding:** Forced RLS, non-owner role, transaction-local context (`set_config(..., true)`), tested.

## DATA-03: HTTP and CDN cache leakage

- **Hunt:** Authenticated or personalized responses without `Cache-Control: private` or `no-store`, `s-maxage` on user-specific pages, missing `Vary: Cookie`, `Authorization`, `Accept-Language`, or `Origin`, framework full-route or data caches applied to personalized pages, ISR on pages that embed user data, `Set-Cookie` on cacheable responses, shared caches keyed only on path.
- **Confirms:** User B receives user A's response. Verify with two sessions and name the cache layer.
- **Not a finding:** Explicit private or no-store on every dynamic route, verified through the deployed edge (check hit/miss headers).

## DATA-04: Web cache deception and poisoning

- **Hunt:** Path-confusion routes that serve dynamic content under static-looking suffixes (`/account/x.css`), unkeyed headers influencing responses (`X-Forwarded-Host`, `X-Original-URL`, locale and device headers), cache keys that normalize differently than the origin, cacheable error pages, reflected values in cached responses.
- **Confirms:** An attacker causes sensitive content to be cached publicly or malicious content to be served to others.
- **Not a finding:** Strict routing, allowlisted cacheable paths, unkeyed inputs ignored.

## DATA-05: Application cache key and authorization staleness

- **Hunt:** Keys missing tenant, user, role, locale, currency, feature flag, or schema version; helper functions that read request context inside a shared cache scope; permission or entitlement results cached longer than revocation requirements; cached negative results; cache-aside updates that race with writes; Redis without authentication, TLS, or network isolation; secrets or personal data cached without TTL or encryption.
- **Confirms:** Cross-user data exposure, stale authorization after revocation, or exposed cache contents.
- **Not a finding:** Keys built from a single scoped helper, short TTL with event invalidation, protected cache endpoint.

## DATA-06: Cache stampede, consistency, and unbounded growth

- **Hunt:** Simultaneous expiry on hot keys, no request coalescing, invalidation before commit, write-through races, user-controlled key cardinality (memory exhaustion), unbounded in-process maps, negative caching of transient errors.
- **Confirms:** A realistic traffic pattern or attacker input causes stale state, outage, or memory exhaustion.
- **Not a finding:** Jittered TTL, coalescing, invalidation after commit, size limits.

## DATA-07: Search indexes and derived stores

- **Hunt:** Indexes shared across tenants without filters, documents indexed with private fields, deletion and permission changes not propagated, autocomplete and facet endpoints leaking counts or values, vector stores and embeddings mixing tenants.
- **Confirms:** Search or retrieval returns another tenant's or unauthorized data.
- **Not a finding:** Tenant-filtered queries enforced server-side and re-checked against the source of truth.

## DATA-08: Exports, reports, and bulk operations

- **Hunt:** CSV or PDF exports built outside the normal authorization path, signed download links without expiry or user binding, bulk endpoints that skip per-object checks, formula injection in CSV, report jobs running with admin context, email attachments of sensitive data.
- **Confirms:** An export includes data the requester cannot otherwise access, or links are shareable bearer tokens for sensitive files.
- **Not a finding:** Exports built through the same scoped queries with expiring bound links.

## DATA-09: Background jobs, queues, and file storage paths

- **Hunt:** Job payloads carrying ids without tenant, workers with global credentials, storage paths derived from user input or lacking tenant segments, shared temp directories, job replays after deletion or role change, poison messages reprocessed forever.
- **Confirms:** A job acts on or exposes data outside the originating principal's scope.
- **Not a finding:** Tenant context carried and revalidated in the worker, isolated paths.

## DATA-10: Retention, deletion, backups, and migrations

- **Hunt:** Deletion that skips caches, indexes, logs, analytics, backups, and processors, no retention schedule for personal data, migrations that copy production data into lower environments, irreversible or locking migrations on hot tables, restore procedures that resurrect deleted personal data without re-applying deletions.
- **Confirms:** Personal data persists after required deletion, or a migration or restore exposes data across trust levels.
- **Not a finding:** Documented retention per data class and a tested deletion pipeline.
