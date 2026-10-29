# Stack Profiles

Load only the profiles detected in Phase 0. Each check is an attack class (`STK-*`) that can be assigned in the ledger. Format: **Hunt** and **Confirms**. Version-specific claims must be verified against the pinned version in the lockfile and the current advisory list; do not rely on this file for exact patch levels.

Highest-yield checks for this stack family, in order:

1. Authorization that lives only in middleware, a proxy, a route guard, or the UI (`STK-NEXT-01`, `STK-NEXT-02`, `STK-NET-01`).
2. Session-scoped database state on pooled connections and non-atomic read-modify-write over HTTP drivers (`STK-NEON-01`, `STK-NEON-02`).
3. Wildcard origins and redirect URIs on shared platform domains (`STK-SEAM-01`).
4. Secrets exposed through client bundles, preview environments, or mobile binaries (`STK-NEXT-04`, `STK-VCL-02`, `STK-FLT-01`).
5. Pipelines that run untrusted code with deploy or publish credentials (see `SUPPLY-CHAIN-AND-CI.md`).
6. Caches that serve personalized responses to other users (`STK-NEXT-05`, `STK-VCL-04`).

---

## Next.js

### STK-NEXT-01: Middleware or proxy is not an authorization boundary

- **Hunt:** Auth decisions made only in `middleware.ts` or the proxy file; matchers that miss data routes, prefetch and `.rsc` requests, locale variants, `/_next/data`, API routes, or Server Actions; trust in internal headers such as `x-middleware-subrequest`; framework versions affected by published middleware or proxy bypass advisories. Multiple advisories exist (for example CVE-2025-29927 and several 2026 CVEs including CVE-2026-44573, CVE-2026-44574, CVE-2026-44575, and CVE-2026-64642): check each against the pinned `next` version and the fixed release in the advisory.
- **Confirms:** A crafted request reaches a protected page, route, or action without the check, on the pinned version or because the handler itself performs no check.
- **Fix direction:** Enforce authentication and authorization inside the data access layer and every Server Action and Route Handler. Use middleware for optimistic redirects only. Strip internal headers at the edge. Upgrade to the advisory-fixed release.

### STK-NEXT-02: Server Actions are public endpoints

- **Hunt:** Actions without authentication, authorization, schema validation, or rate limits; actions returning whole records; trust in closure-captured values; `serverActions.allowedOrigins` widened or unset behind proxies; no `bodySizeLimit`; actions performing privileged work for any caller who finds the action id.
- **Confirms:** An unauthenticated or unauthorized caller can invoke an action and change state or read data.
- **Fix direction:** Treat each action as a POST API: authenticate, authorize on the object, validate with a strict schema, return DTOs, rate limit.

### STK-NEXT-03: React Server Components and Flight deserialization

- **Hunt:** Versions of `react`, `react-dom`, `react-server-dom-*`, and `next` affected by the React2Shell remote code execution advisory (CVE-2025-55182) or its follow-up denial-of-service advisories; custom handling of Flight payloads; server code reachable by unauthenticated POSTs to app routes.
- **Confirms:** An affected version is deployed and reachable. Treat as P0.
- **Fix direction:** Upgrade all related packages together to advisory-fixed releases, redeploy, rotate secrets if exposure is plausible, add WAF rules as a temporary mitigation only.

### STK-NEXT-04: Server and client boundary, environment variables, and bundles

- **Hunt:** `NEXT_PUBLIC_` variables holding secrets (inlined at build time), server-only modules imported into client components, props passing full database rows into client components, `productionBrowserSourceMaps` enabled, secrets present in `.next/static`, missing `import "server-only"` in data access and secret-bearing modules.
- **Confirms:** A secret or privileged field is retrievable from the browser bundle, maps, or serialized props.
- **Fix direction:** `server-only` guards, DTOs for client props, remove secrets from public variables, rotate anything exposed.

### STK-NEXT-05: Caching correctness for the pinned major version

- **Hunt:** Default caching behavior differs across major versions and cache features. For each route verify: use of dynamic APIs (`cookies()`, `headers()`), `fetch` cache options on authenticated requests, `revalidate` and ISR on personalized pages, `unstable_cache` and `use cache` scopes reading request-bound data directly (identity must be an explicit argument so it joins the key), tag keys without tenant, CDN headers on dynamic responses.
- **Confirms:** A two-session test on the deployed URL shows one user's data served to another, or stale data after revocation.
- **Fix direction:** Force dynamic rendering for personalized routes, explicit `Cache-Control: private, no-store`, tenant and user in every cache key.

### STK-NEXT-06: Route Handlers, webhooks, and CORS

- **Hunt:** Webhook signature verification over `await req.json()` instead of the raw body (`await req.text()`), missing signature checks, no replay window or event dedup, hand-written CORS reflecting `Origin`, no method restrictions, handlers exporting `GET` that mutate state, `runtime = "edge"` where Node crypto or libraries are required, no `maxDuration`.
- **Confirms:** A forged or replayed webhook is accepted or a hostile origin reads credentialed responses.
- **Fix direction:** Raw-body HMAC with constant-time compare, timestamp tolerance, processed-event table, exact-origin CORS allowlist.

### STK-NEXT-07: Image optimizer and remote content

- **Hunt:** `remotePatterns` or `domains` too broad, `dangerouslyAllowSVG` without a strict content-security policy, unbounded `deviceSizes` and `minimumCacheTTL` driving cost, SSRF through user-supplied image URLs.
- **Confirms:** The optimizer fetches attacker-chosen hosts, serves active SVG on the app origin, or can be driven to high cost.
- **Fix direction:** Exact host and path patterns, restrict SVG, set limits.

### STK-NEXT-08: Redirects, headers, CSP, and configuration

- **Hunt:** `redirect()` and `NextResponse.redirect` with request-derived URLs, `next` params, missing security headers in `next.config` `headers()`, CSP nonce strategy that disables static rendering unnoticed or reuses nonces across cached responses, `poweredByHeader` enabled, rewrites to internal services forwarding all headers.
- **Confirms:** Open redirect, missing protection that enables another found issue, or header forwarding that leaks internals.
- **Fix direction:** Allowlisted relative redirects, explicit headers, per-request nonces on dynamic routes.

### STK-NEXT-09: Authentication library configuration

- **Hunt:** Auth.js, Clerk, Supabase Auth, custom JWT: `trustHost` or equivalent set broadly, secrets shared across environments, callbacks that skip authorization, redirect callbacks without allowlists, account linking by unverified email, session strategy and cookie flags, role claims trusted without server check.
- **Confirms:** Account takeover, privilege escalation, or open redirect through configuration.
- **Fix direction:** Pin host, per-environment secrets, strict callbacks, verified-email-only linking.

---

## Node.js

### STK-NODE-01: HTTP server hardening

- **Hunt:** Express, Fastify, Nest, Hono, or Koa without body size limits, `x-powered-by` enabled, `trust proxy` set to `true` or absent behind a proxy, missing security header middleware, rate limits in process memory across multiple instances, `server.headersTimeout`, `requestTimeout`, and `keepAliveTimeout` misaligned with the load balancer, `cors()` with reflected origin and credentials.
- **Confirms:** Spoofable client identity, bypassable limits, or avoidable denial of service.
- **Fix direction:** Exact proxy hop trust, shared-store rate limits, aligned timeouts, explicit CORS.

### STK-NODE-02: Async error handling and process lifecycle

- **Hunt:** Express 4 async handlers that reject without being caught (hang or crash, or fail-open when guards are async), `catch` blocks that call `next()` on auth failure, `uncaughtException` handlers that continue running, no graceful shutdown on `SIGTERM`, in-flight work lost on deploy, heap limit not aligned with container memory.
- **Confirms:** A rejection or error changes a deny into an allow, or crashes the service from a single request.
- **Fix direction:** Express 5 or async wrappers, central error handler that fails closed, exit and restart on fatal errors, drain on shutdown.

### STK-NODE-03: Dangerous APIs

- **Hunt:** `child_process.exec` or `shell: true`, `fs` with user paths (resolve and check prefix with `path.sep`), `crypto.timingSafeEqual` without length check, `Math.random` for tokens, `eval` and `vm`, `require` of user input, `Buffer.allocUnsafe` leaks, unbounded `JSON.parse`, `jsonwebtoken` verify without an `algorithms` option.
- **Confirms:** Injection, traversal, or token forgery through the API misuse.
- **Fix direction:** Argument arrays, resolved-path checks, length-checked constant-time compare, CSPRNG, pinned algorithms.

### STK-NODE-04: ORM and query layer

- **Hunt:** Prisma `$queryRawUnsafe`, Drizzle `sql.raw`, Sequelize `literal`, Knex `raw` with interpolation, Mongoose `$where` and operator injection from `req.body` (`strictQuery`, sanitization), dynamic column names, mass assignment through `create(req.body)`.
- **Confirms:** Attacker input reaches query text, operators, or protected fields.
- **Fix direction:** Parameters, allowlists, strict DTO schemas (`strict()`), operator stripping.

### STK-NODE-05: Outbound requests and SSRF

- **Hunt:** `fetch`, `undici`, `axios`, `got` on user URLs without private-range blocking, redirect following, DNS rebinding, missing `AbortSignal.timeout`, response size caps absent.
- **Confirms:** Internal or metadata access, or resource exhaustion through outbound calls.
- **Fix direction:** Resolve and pin IP, deny private and link-local ranges, `redirect: "manual"`, timeouts and size caps.

### STK-NODE-06: Package and runtime posture

- **Hunt:** Missing lockfile enforcement (`npm ci`), install scripts enabled, unsupported Node versions, no `npm audit signatures`, packages with known compromises, dev dependencies in production images, `NODE_ENV` not `production`.
- **Confirms:** A vulnerable or compromised package executes in build or runtime, or debug behavior ships.
- **Fix direction:** Locked installs, `ignore-scripts`, supported LTS, minimal production image.

---

## .NET (ASP.NET Core)

### STK-NET-01: Default-deny authorization

- **Hunt:** No fallback authorization policy, minimal API endpoints or groups without `RequireAuthorization()`, `[AllowAnonymous]` on broad controllers, authorization by role string only for object-level access, resource ownership not checked through `IAuthorizationService` or a scoped query, EF Core global query filters bypassed by `IgnoreQueryFilters` or raw SQL.
- **Confirms:** An unauthenticated or wrong-tenant caller reaches data or an action.
- **Fix direction:** Fallback policy requiring an authenticated user, resource-based authorization, scoped queries plus row-level security where available.

### STK-NET-02: Model binding, over-posting, and serialization

- **Hunt:** Entities bound directly from requests, missing request DTOs, `System.Text.Json` accepting unknown members, Newtonsoft `TypeNameHandling` other than `None`, `BinaryFormatter` or other legacy serializers, `XmlSerializer` and `DataContractSerializer` with attacker-controlled types.
- **Confirms:** Protected fields can be set or types instantiated from input.
- **Fix direction:** Request and response records, `UnmappedMemberHandling.Disallow`, remove unsafe serializers.

### STK-NET-03: EF Core and data access

- **Hunt:** `FromSqlRaw` or `ExecuteSqlRaw` with interpolated strings, Dapper without parameters, dynamic LINQ from user input, read-modify-write without concurrency tokens, `SaveChanges` after external calls inside one transaction.
- **Confirms:** Injection or lost updates reachable from a request.
- **Fix direction:** `FromSql` interpolation (parameterized), `ExecuteUpdateAsync` with predicates, row versions.

### STK-NET-04: JWT bearer, cookies, and antiforgery

- **Hunt:** `TokenValidationParameters` with disabled issuer, audience, lifetime, or signature requirements, default five-minute clock skew where tighter is needed, multi-tenant Entra tokens without `tid` and issuer validation, cookie auth without antiforgery on mutating endpoints, Data Protection keys on ephemeral disk (lost on restart, differing across instances), cookies without `SameSite` or `Secure`.
- **Confirms:** Token forgery or acceptance across tenants or audiences, CSRF, or session breakage that forces unsafe workarounds.
- **Fix direction:** Strict validation parameters, antiforgery, shared persisted Data Protection keys (vault-protected).

### STK-NET-05: Forwarded headers and host filtering

- **Hunt:** `UseForwardedHeaders` missing or placed late, `KnownNetworks` and `KnownProxies` cleared, `AllowedHosts: "*"` in production, `X-Forwarded-*` used for security decisions, redirects and links built from unvalidated host.
- **Confirms:** Spoofed client IP, scheme, or host bypasses a control or poisons links.
- **Fix direction:** Explicit trusted proxies, specific allowed hosts.

### STK-NET-06: Environment, diagnostics, and limits

- **Hunt:** Developer exception page or detailed errors in production, Swagger UI exposed, `ASPNETCORE_ENVIRONMENT` not `Production`, missing HSTS and HTTPS redirection, Kestrel body, header, and timeout limits unset, in-memory rate limiter assumed global across instances, `.Result` and `.Wait()` on async code, `HttpClient` created per request or without timeouts, missing `CancellationToken` propagation.
- **Confirms:** Information disclosure or denial of service from the configuration.
- **Fix direction:** Production defaults, `IHttpClientFactory` with timeouts and resilience handlers, distributed rate limiting.

### STK-NET-07: CORS, secrets, and NuGet

- **Hunt:** `AllowAnyOrigin` combined with credential workarounds (`SetIsOriginAllowed(_ => true)`), secrets in `appsettings*.json`, user secrets used outside development, no Key Vault references, no NuGet lock files or package source mapping, NuGet Audit disabled, vulnerable packages present.
- **Confirms:** Credentialed cross-origin reads, committed secrets, or dependency risk.
- **Fix direction:** Exact origins, vault-backed secrets with managed identity, locked restore, audit enabled.

---

## Neon (serverless Postgres)

### STK-NEON-01: Pooled connections and session state

- **Hunt:** Application using the pooled (`-pooler`) endpoint with features that need a session: `SET` or `RESET`, `LISTEN` and `NOTIFY`, session-level advisory locks, SQL-level `PREPARE`, session `search_path`. Tenant or user context set with session-level `SET` for row-level security (leaks or vanishes across clients in transaction pooling).
- **Confirms:** Tenant context bleeds between requests or locks are not held as assumed.
- **Fix direction:** Set context with `set_config(name, value, true)` inside an explicit transaction, use transaction-level advisory locks, use the direct endpoint for migrations and session features.

### STK-NEON-02: Serverless driver transaction semantics

- **Hunt:** The HTTP query function used for multi-statement logic: each call is its own transaction, so `SELECT ... FOR UPDATE` followed by `UPDATE` in separate calls does not hold the lock. Read-modify-write balances, stock, or counters across separate HTTP calls.
- **Confirms:** Concurrent requests produce double spend or oversell. Provide the interleaving.
- **Fix direction:** Use a WebSocket `Pool` or `Client` with an interactive transaction, a single atomic SQL statement, or the driver's batch transaction function for non-interactive sets.

### STK-NEON-03: Roles, ownership, and row-level security

- **Hunt:** Application using `neondb_owner` or another owner role at runtime, runtime role with `BYPASSRLS`, tables owned by the runtime role (owners bypass RLS unless forced), policies without `WITH CHECK`, `PUBLIC` allowed to create in the public schema, one role for migrations and runtime.
- **Confirms:** The runtime connection can read or alter data beyond its need or bypass row-level security.
- **Fix direction:** Separate migration and runtime roles, non-owner runtime role, `FORCE ROW LEVEL SECURITY`, revoke defaults.

### STK-NEON-04: Connection strings and client exposure

- **Hunt:** Connection strings in `NEXT_PUBLIC_*`, Flutter code, browser bundles, mobile configs, or client-callable edge code; the database reachable directly from clients without a deliberate Data API plus RLS design.
- **Confirms:** A credential with database access is exposed to clients.
- **Fix direction:** Server-only variables, API layer between clients and database, rotate exposed credentials (reset the role password).

### STK-NEON-05: Branches, preview data, and environments

- **Hunt:** Preview or development branches created from production with personal data, preview deployments pointing at the production branch, stale branches with live credentials, shared credentials across branches, no anonymization.
- **Confirms:** Production data is reachable from lower-trust environments.
- **Fix direction:** Schema-only or anonymized branches, per-branch credentials, deletion of stale branches.

### STK-NEON-06: Transport, network, and operations

- **Hunt:** TLS mode below `require`, channel binding not used where supported, no IP allowlist or private networking where the plan supports it, no connection and statement timeouts for cold starts and autosuspend, no autoscaling ceiling (cost), compute region far from the application region (latency-driven timeouts), untested point-in-time restore.
- **Confirms:** Interception, uncapped cost, or unrecoverable failure.
- **Fix direction:** `sslmode=require` at minimum, limits, colocated regions, tested restore through a branch from a past point.

---

## Azure

### STK-AZ-01: Identity and secrets

- **Hunt:** Client secrets or connection strings where managed identity is possible, Key Vault using access policies with broad rights instead of RBAC, secrets visible in App Service settings or deployment slots, expired or non-rotating app registration secrets, CI using stored credentials instead of workload identity federation.
- **Confirms:** A long-lived credential is exposed to broader audiences than needed.
- **Fix direction:** Managed identity, Key Vault references, federated credentials with subject scoped to repository and environment.

### STK-AZ-02: Microsoft Entra ID app registrations

- **Hunt:** Wildcard or localhost redirect URIs in production, implicit flow enabled, multi-tenant apps accepting any `tid` or issuer, no `aud` validation, group claims overage mishandled, broad delegated or application permissions with admin consent, missing app role assignment requirements.
- **Confirms:** Token theft, cross-tenant acceptance, or excessive privilege.
- **Fix direction:** Exact redirects, issuer and audience validation, least-privilege permissions, assignment required.

### STK-AZ-03: App Service, Functions, and Container Apps

- **Hunt:** HTTP allowed (HTTPS only off), TLS below 1.2, FTP or FTPS enabled, SCM basic authentication enabled, remote debugging on, public admin access without restrictions or private endpoints, anonymous HTTP triggers meant to be private, function keys used as user authentication, container registry admin user enabled.
- **Confirms:** An unauthenticated or weakly authenticated management or invocation path exists.
- **Fix direction:** Disable legacy protocols and basic auth, access restrictions, Entra authentication, managed identity pulls.

### STK-AZ-04: Edge and origin lock-down

- **Hunt:** Front Door or Application Gateway WAF in detection mode, origin App Service still reachable on `azurewebsites.net` without restriction, no validation of the Front Door id header and service tag restriction.
- **Confirms:** WAF and rate limits can be bypassed by hitting the origin directly.
- **Fix direction:** Prevention mode, origin restricted by service tag plus header validation or private link.

### STK-AZ-05: Storage and data services

- **Hunt:** Public blob access allowed, shared key access enabled, account-level SAS with long expiry, no user delegation SAS, SQL or PostgreSQL firewall with "Allow Azure services" (permits any Azure tenant's resources), public network access with weak auth, missing auditing and soft delete.
- **Confirms:** Data reachable by unauthorized parties or from other tenants' Azure resources.
- **Fix direction:** Entra authentication, private endpoints, short user-delegation SAS, soft delete and versioning.

### STK-AZ-06: Metadata and SSRF

- **Hunt:** Fetchers able to reach `169.254.169.254`, App Service identity endpoint (`IDENTITY_ENDPOINT`) and its secret header, forwarding of arbitrary headers to internal calls.
- **Confirms:** An SSRF can obtain managed identity tokens.
- **Fix direction:** Block link-local ranges in fetchers, do not forward arbitrary headers, scope identity permissions narrowly.

### STK-AZ-07: Monitoring and cost control

- **Hunt:** No diagnostic settings to Log Analytics, no alerts for auth failures, Key Vault access, or privilege changes, Defender for Cloud not enabled, no budgets and alerts, Application Insights capturing personal data or tokens.
- **Confirms:** Attacks and runaway cost go unnoticed.
- **Fix direction:** Diagnostics, alert rules, budgets, telemetry scrubbing.

---

## Render

### STK-RND-01: Public exposure and origin lock-down

- **Hunt:** Services that should be private exposed on public `onrender.com` URLs, a CDN or WAF in front while the origin accepts direct traffic, databases or key-value stores with permissive external access lists, internal services calling each other over public URLs.
- **Confirms:** Edge controls are bypassable or internal services are internet-reachable.
- **Fix direction:** Private services and internal addresses, origin secret header or network restrictions, locked external access lists.

### STK-RND-02: Client IP, proxy trust, and multi-instance state

- **Hunt:** `trust proxy` not set (all clients appear as the proxy) or set too broadly, rate limits and sessions in process memory across instances, in-memory locks, local disk used for uploads or keys (ephemeral and single-instance), .NET Data Protection keys on local disk.
- **Confirms:** Rate limits and locks do not work across instances, or user data and keys are lost or mixed.
- **Fix direction:** Correct proxy hop trust, shared stores, object storage, external key store.

### STK-RND-03: Secrets, blueprints, and previews

- **Hunt:** `render.yaml` with committed secret values (use `sync: false` or secret files), env groups shared between production and previews, preview environments with production credentials or production database, deploy hook URLs committed or shared, broad team roles. Verify whether pull request previews can be triggered from forks and what they inherit.
- **Confirms:** Secrets or production data accessible to lower-trust contexts.
- **Fix direction:** Secret-free blueprints, separate env groups, preview-specific credentials, rotate deploy hooks.

### STK-RND-04: Deploys, jobs, and migrations

- **Hunt:** Overlapping instances during zero-downtime deploys running the same cron or background work, migrations that lock hot tables or are not backward compatible, no pre-deploy migration step using the direct database URL, health checks hitting the database, free-tier spin-down causing timeouts in webhooks and callbacks.
- **Confirms:** Duplicate side effects, deploy-time outages, or missed webhooks.
- **Fix direction:** Idempotent jobs with leader election or database locks, expand-and-contract migrations, minimal health checks, paid tier for webhook receivers.

### STK-RND-05: Limits and cost

- **Hunt:** Autoscaling without a maximum, memory limits causing out-of-memory kills for Node heaps, request timeout limits at the proxy that cut long requests, bandwidth costs, no alerting.
- **Confirms:** Denial of wallet or instability under load.
- **Fix direction:** Scaling ceilings, heap aligned to instance memory, async jobs for long work, spend alerts.

---

## Vercel

### STK-VCL-01: Deployment protection and preview exposure

- **Hunt:** Preview and branch URLs publicly accessible with staging or real data, deployment protection disabled, shareable links without expiry, production domain aliases pointing at unvetted deployments, Git integration deploying forks without approval.
- **Confirms:** Non-production environments expose data or functionality.
- **Fix direction:** Enable protection for previews, separate data, require approval for external contributors.

### STK-VCL-02: Environment variables and secrets

- **Hunt:** Variables scoped to all environments by default, production secrets present in Preview and Development, secrets not marked sensitive, `NEXT_PUBLIC_` secrets, secrets visible in build logs, long-lived cloud keys where OIDC federation is possible.
- **Confirms:** Secret reachable by preview builds, other team members, or the browser.
- **Fix direction:** Per-environment scoping, sensitive variables, OIDC federation, rotation.

### STK-VCL-03: Cron, webhooks, and public function paths

- **Hunt:** Cron routes callable by anyone because the handler does not verify the `CRON_SECRET` bearer header, internal-only handlers on public paths, deploy and revalidation endpoints without secrets, webhooks without signature verification.
- **Confirms:** Anyone can trigger privileged background work or revalidation.
- **Fix direction:** Verify the secret header in the handler, signature checks for webhooks.

### STK-VCL-04: CDN caching and shared function instances

- **Hunt:** `s-maxage`, `CDN-Cache-Control`, or `Vercel-CDN-Cache-Control` on personalized responses, ISR pages embedding user data, `x-vercel-cache: HIT` on authenticated routes, module-scope mutable variables (user, tenant, request data) shared across concurrent invocations on warm or concurrent instances.
- **Confirms:** One user receives another user's response or data through the CDN or shared module state.
- **Fix direction:** Private no-store on dynamic routes, request-scoped state only.

### STK-VCL-05: Limits, spend, firewall, and region

- **Hunt:** No `maxDuration` or memory settings, platform request body limits assumed rather than enforced, no spend management or alerts, no firewall rules or rate limits on expensive routes, no bot protection on signup and checkout, function region far from the database, log drains carrying personal data, Edge runtime used for code needing Node APIs (silent security library gaps).
- **Confirms:** Denial of wallet, timeouts that push unsafe retries, or personal data leakage into logs.
- **Fix direction:** Limits, spend caps, firewall rules, colocated regions, scrubbed log drains, Node runtime for security-sensitive code.

---

## Flutter

### STK-FLT-01: Secrets and build configuration

- **Hunt:** Secrets in Dart source, assets, or `--dart-define` (extractable from the binary), unrestricted API keys, Firebase security rules open or untested, App Check not enforced, shared keys across flavors, release builds without separate flavor configuration, debug endpoints in release.
- **Confirms:** A powerful key is extractable or backend rules allow unauthorized access.
- **Fix direction:** Backend-held secrets, key restrictions by package and bundle id, tested security rules, App Check, flavors per environment.

### STK-FLT-02: Token and data storage

- **Hunt:** Tokens in `SharedPreferences`, Hive, or files; `flutter_secure_storage` missing or with weak accessibility options; unencrypted local databases; backups of sensitive data enabled; logs containing tokens (`print`, `debugPrint` not stripped).
- **Confirms:** Credentials or personal data recoverable from device storage, backups, or logs.
- **Fix direction:** Keychain and Keystore via secure storage, encrypted databases, backup exclusion, release logging stripped.

### STK-FLT-03: Transport and pinning

- **Hunt:** `badCertificateCallback` returning true, `HttpOverrides` disabling verification, cleartext allowed in Android network security config or iOS ATS exceptions, pinning absent where the threat model needs it or implemented without rotation (lockout risk).
- **Confirms:** Network attacker can intercept credentialed traffic.
- **Fix direction:** Default validation, cleartext disabled, pinning with backup pins where warranted.

### STK-FLT-04: Authentication and deep links

- **Hunt:** OAuth via embedded WebView, custom schemes for redirects, no PKCE, `local_auth` biometrics as the only gate with no key binding, `go_router` redirect guards treated as authorization, unvalidated deep link parameters, auth state trusted from local storage.
- **Confirms:** Intercepted codes, bypassed local gates, or actions triggered through links without server authorization.
- **Fix direction:** System browser with PKCE (`flutter_appauth` or equivalent), claimed https links, biometric-bound keys, server-side authorization.

### STK-FLT-05: WebViews and platform channels

- **Hunt:** `webview_flutter` with unrestricted JavaScript, no navigation delegate allowlist, JavaScript channels exposing privileged functions to remote content, platform channel handlers trusting arguments, plugins with broad native permissions.
- **Confirms:** Remote or injected content reaches native capabilities.
- **Fix direction:** Allowlisted navigation, minimal channels with validation, plugin review.

### STK-FLT-06: Platform configuration and release

- **Hunt:** `allowBackup`, `debuggable`, exported components, missing `FLAG_SECURE` on sensitive screens, background snapshot exposure on iOS, release signing keys in repositories, no obfuscation and symbol handling policy (`--obfuscate --split-debug-info` raises effort only), dependency lock (`pubspec.lock`) not committed, git dependencies unpinned.
- **Confirms:** Configuration enables data exposure or tampering.
- **Fix direction:** Hardened manifests and entitlements, secure signing, committed locks, pinned git dependencies. Scan `pubspec.lock` with a dependency scanner that supports Dart.

### STK-FLT-07: Client trust

- **Hunt:** Prices, entitlements, and roles computed client-side, purchases not verified server-side, root or jailbreak detection and attestation treated as authorization, no mobile rate limits.
- **Confirms:** A modified client gains paid features or access.
- **Fix direction:** Server-side verification and enforcement, attestation as a signal only.

---

## Cross-stack seams

Run these when two or more profiles are detected. They catch failures that only appear where platforms meet.

### STK-SEAM-01: Shared platform domains in allowlists

- **Hunt:** CORS origins, OAuth and OIDC redirect URIs, CSP sources, cookie domains, and trusted-host lists containing `*.vercel.app`, `*.onrender.com`, `*.azurewebsites.net`, or other shared suffixes (anyone can host a page there).
- **Confirms:** An attacker-hosted page on the shared suffix passes an origin or redirect check.
- **Fix direction:** Exact hostnames per environment.

### STK-SEAM-02: Service-to-service authentication

- **Hunt:** Next.js on Vercel calling an Azure or Render API with a static shared key reused across preview and production, no audience binding, keys in preview environments.
- **Confirms:** A preview deployment or leaked key can call production APIs.
- **Fix direction:** Entra client credentials, OIDC federation, or signed short-lived tokens with audience validation, separate per environment.

### STK-SEAM-03: Forwarded header chain

- **Hunt:** CDN to proxy to origin to framework chains where each hop trusts or overwrites client IP, scheme, and host differently.
- **Confirms:** Spoofed IP, host, or scheme at the application.
- **Fix direction:** One trusted source of client IP per hop, strip client-supplied forwarding headers at the edge.

### STK-SEAM-04: Token systems across clients

- **Hunt:** Browser sessions (cookies) and Flutter bearer tokens validated by different code paths, inconsistent expiry, revocation, and claims checks, refresh tokens without rotation.
- **Confirms:** One client type bypasses controls enforced for the other.
- **Fix direction:** Single authorization layer in the API for every client.

### STK-SEAM-05: Environment chains

- **Hunt:** Vercel preview to staging API to production database, shared Neon branches, shared secrets, shared queues.
- **Confirms:** A preview or staging path touches production data.
- **Fix direction:** Preview to staging to isolated database branch with distinct secrets.

### STK-SEAM-06: Webhook ingress and idempotency

- **Hunt:** Multiple ingress points for the same provider, raw-body requirements broken by framework parsing, dedup tables missing in the database, provider retries hitting cold-start timeouts.
- **Confirms:** Forged, replayed, or lost events.
- **Fix direction:** One ingress, raw-body verification, processed-event table, fast acknowledge with async processing.

### STK-SEAM-07: Region, timeout, and deadline alignment

- **Hunt:** Function, API, and database regions mismatched, timeouts not nested (client below edge below API below database), deadlines not propagated, retries at several layers multiplying load.
- **Confirms:** Timeouts and retries amplify failures into outages or duplicate side effects.
- **Fix direction:** Nested timeouts, single retry layer, idempotent writes.

### STK-SEAM-08: Cost ceilings across platforms

- **Hunt:** No spend caps on Vercel, Render autoscaling maximum, Azure budgets, or Neon compute maximums; unauthenticated endpoints that trigger paid work.
- **Confirms:** An attacker or bug can create large unbounded cost.
- **Fix direction:** Caps and alerts on every platform, authentication and rate limits on expensive routes.
