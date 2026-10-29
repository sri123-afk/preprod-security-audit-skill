# Web Protocol and Authentication Classes (WEB-01 to WEB-18)

Use for any HTTP-facing unit, auth flow, proxy, or API surface. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## WEB-01: Authentication enforced on every route

- **Hunt:** Public-by-default routers, routes added outside the guarded group, health, metrics, debug, cron, and preview endpoints, internal APIs reachable from the internet, auth implemented only in middleware, a proxy, or the UI.
- **Confirms:** An unauthenticated request reaches data or an action that requires identity.
- **Not a finding:** Default-deny with explicit public allowlist and tests per route.

## WEB-02: Transport and routing variants

- **Hunt:** For each protected resource, enumerate every way to reach it: trailing slash, case, encoded slashes and dots, double encoding, HTTP method override, `HEAD`/`OPTIONS`, alternate content types, framework data routes (`.rsc`, prefetch, `/_next/data`, locale-less paths, `.json` suffixes), versioned or legacy APIs, internal rewrites, WebSocket upgrades, HTTP/2 pseudo-headers, spoofable internal headers (`x-middleware-subrequest` style).
- **Confirms:** A variant skips a check the canonical path enforces. Provide the exact request.
- **Not a finding:** Authorization enforced inside the handler or data function for every variant, or the variant provably normalizes to the checked path in the pinned version.

## WEB-03: OAuth and OIDC

- **Hunt:** `redirect_uri` not exact-matched or allowing platform wildcards (`*.vercel.app`, `*.onrender.com`, `*.azurewebsites.net`), missing `state`, `nonce`, or `PKCE`, implicit flow, tokens in URLs, account linking on unverified email (pre-hijack), multi-tenant issuer not validated (`iss`, `tid`), `aud` not checked, open redirect after login, trusting `email` claim without `email_verified`.
- **Confirms:** An attacker obtains a victim's code or token, logs in as the victim, or links their identity to the victim's account.
- **Not a finding:** Exact redirect allowlist, PKCE, state and nonce verified, verified-email-only linking.

## WEB-04: Session management

- **Hunt:** No rotation on login or privilege change (fixation), missing `HttpOnly`, `Secure`, `SameSite`, `__Host-` prefix, no idle or absolute timeout, logout that does not invalidate server state, session ids in URLs or logs, sessions not revoked on password change, signing keys shared across environments.
- **Confirms:** A stolen, fixed, or stale session grants access it should not.
- **Not a finding:** Rotated ids, secure flags, server-side invalidation.

## WEB-05: JWT and bearer token validation

- **Hunt:** `alg: none`, RS256/HS256 confusion, algorithm not pinned, `kid`, `jku`, `x5u` injection, missing `iss`, `aud`, `exp`, `nbf` checks, huge clock skew, long-lived tokens without revocation, role claims trusted after role change, tokens accepted from query strings, symmetric secrets that are short or default.
- **Confirms:** A forged or stale token is accepted, or claims from another audience or tenant are accepted.
- **Not a finding:** Pinned algorithm and key, all standard claims validated, short TTL, revocation path.

## WEB-06: CSRF

- **Hunt:** State-changing routes on cookie auth without SameSite plus token or custom-header protection, `SameSite=None`, GET with side effects, CORS that lets attacker origins read tokens, Server Actions or form handlers behind proxies where origin checks are disabled or widened, JSON endpoints accepting `text/plain` or form encodings.
- **Confirms:** A cross-site page can make a state-changing authenticated request.
- **Not a finding:** SameSite Lax or Strict with no GET side effects and strict origin checks, or token-based CSRF defenses verified on all mutating routes.

## WEB-07: Password reset, invites, verification, enumeration

- **Hunt:** Reusable or long-lived tokens, tokens stored unhashed, tokens in `Referer` or logs, reset links built from the `Host` header, no session invalidation after reset, user enumeration via response text, status code, or timing, email change without re-authentication, invite tokens guessable or not bound to the invitee.
- **Confirms:** An attacker can take over an account or learn account existence at scale.
- **Not a finding:** Single-use hashed tokens, short TTL, fixed base URL, uniform responses.

## WEB-08: MFA, OTP, recovery, and identifier canonicalization

- **Hunt:** MFA bypass through alternate endpoints or API versions, unthrottled OTP verification, OTP reuse, recovery codes stored unhashed, SMS pumping and toll fraud, email bombing, duplicate accounts through case, Unicode (NFKC), plus-addressing, trailing dots, or homoglyphs, weak password hashing (MD5, SHA-*, low-cost bcrypt), no breach check.
- **Confirms:** Brute force, bypass, duplicate-account takeover, or uncapped cost.
- **Not a finding:** Attempt limits with backoff, hashed recovery codes, canonicalized uniqueness checks, Argon2id or equivalent.

## WEB-09: Webhook and callback ingress

- **Hunt:** Public webhook routes without signature verification, verification on parsed JSON instead of raw body (Next.js route handlers must read `req.text()`), replay window too wide or absent, processed-event dedup missing, secrets shared across environments, webhook URLs that act as bearer secrets, outbound webhooks that can be pointed at internal addresses.
- **Confirms:** A forged or replayed webhook changes state, or an outbound webhook reaches an internal target.
- **Not a finding:** Raw-body HMAC, timestamp tolerance, unique event id stored transactionally.

## WEB-10: Request smuggling, desync, and header injection

- **Hunt:** Disagreement between proxy and origin on `Content-Length` vs `Transfer-Encoding`, HTTP/2 downgrade, CRLF in values placed in headers or redirects, user input in `Set-Cookie`, `Location`, or `Content-Disposition`, hop-by-hop headers forwarded, old proxy or server versions with known desync bugs.
- **Confirms:** A request can be split, poisoned, or have headers injected through attacker data. Name the component pair.
- **Not a finding:** Modern proxy end-to-end HTTP/2, ambiguous framing rejected, header values encoded.

## WEB-11: CORS and origin validation

- **Hunt:** Reflected `Origin` with credentials, substring or regex origin checks, `null` origin allowed, wildcard subdomains on shared platforms, `SetIsOriginAllowed(_ => true)`, missing `Vary: Origin`, preview domains allowed in production, permissive `Access-Control-Allow-Headers`.
- **Confirms:** A hostile origin can read credentialed responses.
- **Not a finding:** Exact parsed-origin allowlist, credentials only for those origins.

## WEB-12: Server-side request forgery

- **Hunt:** URL fetchers, image proxies, PDF and screenshot renderers, webhook senders, "import from URL", OAuth discovery, link previews, SSO metadata fetchers. Check IPv6, decimal and octal IPs, DNS rebinding (resolve then connect), redirects, `file://`, `gopher://`, link-local and cloud metadata ranges (`169.254.169.254`, IMDS, `IDENTITY_ENDPOINT`), forwarded headers.
- **Confirms:** Attacker-controlled URL makes the server reach an internal or metadata address or leak credentials.
- **Not a finding:** Resolve once and pin the IP, deny private ranges, no cross-origin redirects, egress allowlist.

## WEB-13: Open redirect

- **Hunt:** `next`, `returnUrl`, `redirect_uri`, `continue` parameters, `redirect()` with request data, `Location` built from the `Host` header, protocol-relative and backslash tricks.
- **Confirms:** Redirect to an attacker origin, especially after login or inside an OAuth flow (raise severity when it chains to token theft).
- **Not a finding:** Relative-path-only allowlists with parsing, not substring checks.

## WEB-14: Proxy header and client IP trust

- **Hunt:** `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `Host`, `X-Forwarded-Host` trusted from any client, `trust proxy` set to `true`, ASP.NET forwarded-headers known networks cleared, rate limits and allowlists keyed on spoofable IPs, origin reachable directly so edge protections can be bypassed.
- **Confirms:** An attacker spoofs IP, host, or scheme to bypass a control or poison a link or cache.
- **Not a finding:** Trusted hop count or CIDRs verified, origin locked to the edge.

## WEB-15: TLS and transport

- **Hunt:** HTTP fallback, missing HSTS, TLS verification disabled (`rejectUnauthorized: false`, `badCertificateCallback`, `ServerCertificateCustomValidationCallback` returning true), old protocols, mixed content, internal traffic in clear text across trust boundaries.
- **Confirms:** Traffic carrying credentials or personal data can be intercepted or modified.
- **Not a finding:** Local development configs that cannot ship.

## WEB-16: Security headers and CSP

- **Hunt:** Missing or weak CSP (`unsafe-inline`, wildcard sources), no `frame-ancestors`, missing `nosniff`, `Referrer-Policy`, `Permissions-Policy`, cookies without prefixes, CSP nonces reused across requests or cached, verbose `Server` and `X-Powered-By`.
- **Confirms:** Missing header materially enables a concrete attack found elsewhere. Otherwise report as P3 hardening.
- **Not a finding:** Header gaps with no exploit path (hardening only).

## WEB-17: File serving, uploads, and content types

- **Hunt:** User content served from the application origin, `Content-Type` from the client, `nosniff` absent, SVG or HTML inline, signed upload URLs without size, type, and key constraints, public object storage listing, range-request and cache issues on private files.
- **Confirms:** Stored active content executes on the application origin, or private files are fetchable.
- **Not a finding:** Isolated download origin with `Content-Disposition: attachment` and private bucket with short-lived signed URLs.

## WEB-18: GraphQL and API surface specifics

- **Hunt:** Introspection and playground in production, no depth, complexity, or alias limits, batch queries for credential brute force, per-field authorization missing, resolvers trusting parent objects, N+1 amplification, mutation side effects on queries, verbose errors, REST endpoints with `expand` or `include` parameters that bypass field rules.
- **Confirms:** Authorization bypass, brute force amplification, or unbounded cost through the API shape.
- **Not a finding:** Limits and field-level auth enforced and tested.
