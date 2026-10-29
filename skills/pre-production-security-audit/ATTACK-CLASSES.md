# Core Attack Classes (CORE-01 to CORE-16)

Each class gives three things: what to **Hunt**, what **Confirms** a finding, and what is **Not a finding**. Follow data from source to sink and name the check that should have stopped it.

## CORE-01: SQL and NoSQL injection

- **Hunt:** String-built queries, `$queryRawUnsafe`, `sql.raw`, `FromSqlRaw` with interpolation, ORM `literal`, dynamic `ORDER BY` or column names, Mongo operators from `req.body` (`$where`, `$gt`, `$ne`), `LIKE` patterns, JSON path operators.
- **Confirms:** Attacker-controlled value reaches the query text or operator position without parameterization or an allowlist, in a reachable route.
- **Not a finding:** Values bound as parameters; identifiers chosen from a fixed allowlist; constants only.

## CORE-02: OS command and argument injection

- **Hunt:** `exec`, `execSync`, `spawn` with `shell: true`, `Process.Start` with concatenated arguments, backticks, `system()`, image or PDF tools invoked with user-controlled filenames or flags (leading `-`), `git` or `curl` invoked with user URLs.
- **Confirms:** Attacker input reaches a shell string or an argument position that changes behavior (option injection counts).
- **Not a finding:** Argument arrays without a shell and with `--` terminators; fixed commands.

## CORE-03: Signature, HMAC, and token verification flaws

- **Hunt:** Non-constant-time comparison, comparison after UTF-8 or string conversion, missing length check (`timingSafeEqual` throws on mismatch and many handlers fail open on the exception), signature over parsed JSON instead of raw bytes, empty or truncated signature accepted, missing timestamp tolerance, algorithm taken from the token, same key reused across purposes.
- **Confirms:** A forged, truncated, replayed, or re-encoded message is accepted, or the verifier can be made to skip.
- **Not a finding:** Verification over raw bytes, constant-time, length-checked, with replay window and idempotency.

## CORE-04: Template injection and unsafe evaluation

- **Hunt:** User input concatenated into template source before compilation (Jinja, Handlebars, Razor, EJS, Liquid), `eval`, `new Function`, `vm.runInContext`, expression languages, dynamic `import()` or `require()` of user paths, `unserialize`-style gadgets.
- **Confirms:** Attacker text is compiled or evaluated as code or template.
- **Not a finding:** User data passed as template variables with auto-escaping on and no source concatenation.

## CORE-05: Path traversal, file handling, and upload abuse

- **Hunt:** `path.join` or `Path.Combine` with user segments, missing canonicalization plus prefix check, symlink following, Zip Slip in archive extraction, user-controlled filenames and extensions, MIME trusted from the client, SVG or HTML uploads served inline, uploads inside the web root, polyglots, image parsers on untrusted input.
- **Confirms:** A crafted path or archive entry reads or writes outside the intended directory, or an upload executes or renders as active content on the application origin.
- **Not a finding:** Random server-generated names, resolved-path prefix checks with separator, uploads served from an isolated origin with `Content-Disposition: attachment`.

## CORE-06: Deserialization, prototype pollution, and mass assignment

- **Hunt:** `BinaryFormatter`, `TypeNameHandling` other than `None`, `pickle`, `yaml.load`, `ObjectInputStream`, `unserialize`, `node-serialize`, RSC/Flight payload handling on unpatched versions, recursive merge or `Object.assign` of request data, `__proto__` and `constructor.prototype` keys, ORM `create(req.body)`, `[Bind]` over entities, binding `role`, `isAdmin`, `tenantId`, `price`, `status`.
- **Confirms:** Attacker data instantiates types, pollutes prototypes, or sets protected fields.
- **Not a finding:** Schema-validated DTOs with `strict()` or `UnmappedMemberHandling.Disallow`, `Object.create(null)` targets, explicit allowlists.

## CORE-07: Broken access control at the data layer (BOLA, BFLA, BOPLA)

- **Hunt:** Every object id in path, query, body, header, and GraphQL args resolved without an ownership or tenant predicate; admin or internal functions reachable by ordinary roles; methods that skip checks the others have; fields readable or writable beyond the caller's role; role taken from a stale token claim.
- **Confirms:** A user of role or tenant A can read or change an object belonging to B by changing an id, method, or field. State both principals and the request.
- **Not a finding:** Ownership and tenant predicates in the query itself, or row-level security proven active for the runtime role.

## CORE-08: Input validation and schema trust

- **Hunt:** Missing type, length, range, and enum validation at the boundary; validation only on the client; parsing that accepts arrays or objects where scalars are expected; unbounded pagination; numeric strings, negative numbers, NaN, huge integers; Unicode normalization differences between validator and consumer.
- **Confirms:** Unvalidated input reaches a sink in a way that changes security behavior (not just a 500).
- **Not a finding:** Validation gaps whose only effect is a handled validation error.

## CORE-09: Client-supplied price, quantity, currency, and tax

- **Hunt:** Prices, discounts, totals, tax rates, currency, shipping, and plan ids accepted from the client; negative or fractional quantities; fulfillment triggered by browser redirect; cart not bound to the payment intent; guest checkout URLs without signature or expiry.
- **Confirms:** An attacker pays less than the true amount or receives goods without a verified payment.
- **Not a finding:** Server recomputes in integer minor units from server-side catalog and binds the cart hash to the intent.

## CORE-10: Race conditions and TOCTOU

- **Hunt:** Read-then-write on balances, stock, coupons, rate counters, uniqueness (`SELECT` then `INSERT`), double submit on refund or payout, in-process locks used across replicas, advisory locks held on pooled sessions, optimistic updates without version checks, check in one transaction and use in another, HTTP-driver database clients where each statement is its own transaction.
- **Confirms:** Concurrent requests produce an invalid end state (double spend, oversell, duplicate redemption). Provide the interleaving.
- **Not a finding:** Atomic conditional updates, `SELECT ... FOR UPDATE` inside one transaction, unique constraints, serializable isolation where needed.

## CORE-11: Idempotency and replay

- **Hunt:** Payment, order, email, and webhook handlers with no idempotency key or processed-event table; retries that repeat side effects; reusable single-use tokens (reset, invite, magic link, OTP); replayable signed URLs.
- **Confirms:** A repeated request repeats a side effect that should happen once.
- **Not a finding:** Unique constraint on key or event id enforced in the same transaction as the effect.

## CORE-12: Webhook and callback ordering and authenticity

- **Hunt:** Out-of-order events overwriting newer state, trusting event payload status without re-fetching from the provider, no source authentication, tolerance windows that are too large, secrets shared across environments, acceptance on a public route with no signature.
- **Confirms:** A forged, stale, or reordered event changes order, entitlement, or balance state.
- **Not a finding:** Signed, timestamped, deduplicated events applied through a monotonic state machine.

## CORE-13: State machine and workflow bypass

- **Hunt:** Steps that can be skipped or repeated (pay after cancel, ship before pay, approve own request, re-open closed items), transitions enforced only in the UI, status fields writable by the client.
- **Confirms:** An illegal transition succeeds through a reachable request.
- **Not a finding:** Single transition table enforced server-side with preconditions in the update statement.

## CORE-14: Business logic abuse

- **Hunt:** Coupon stacking or replay, referral and credit loops, refund greater than payment, free-trial re-registration with alias emails, negative balances, integer overflow, rounding drift in splits, limits enforced per request instead of per account, gift-card or wallet enumeration.
- **Confirms:** A documented rule can be violated for gain with a concrete request sequence.
- **Not a finding:** Product decisions without an exploit path; abuse that costs the attacker more than the gain and is bounded.

## CORE-15: Error handling and fail-open logic (OWASP A10)

- **Hunt:** `catch` blocks that log and continue on security paths, middleware that calls `next()` after an auth error, policy checks that return allow on exception or timeout, default-allow when a dependency is down, partial commits after a failure, unhandled promise rejections in guards, stack traces and internal ids in responses, retries that skip checks.
- **Confirms:** Inducing an error, timeout, or malformed input changes a deny into an allow, or leaves a security-relevant half-written state.
- **Not a finding:** Errors that fail closed with generic messages and a correlation id.

## CORE-16: Wildcard and obvious things

- **Hunt:** After assigned classes, ask what a motivated attacker would try that no class names. Also check the obvious: hardcoded credentials, default passwords, debug flags and test headers active in production, seed or reset routes, disabled TLS verification, `*` CORS with credentials, public buckets, admin panels, forgotten endpoints, copied sample code.
- **Confirms:** Same standard as every other class: source, missing check, sink, impact.
- **Not a finding:** Speculation without a traced path. Record as `needs_validation` with the unresolved fact.
