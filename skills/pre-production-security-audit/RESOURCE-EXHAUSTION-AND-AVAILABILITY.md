# Resource Exhaustion and Availability Classes (RES-01 to RES-12)

Use for parsers, uploads, regex, queues, retries, outbound calls, rate limits, and anything where an attacker (or a bug) can consume shared CPU, memory, connections, quota, or money. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## RES-01: Regular expression denial of service

- **Hunt:** Nested quantifiers and overlapping alternations on user input (`(a+)+`, `(.*a){n}`), validators for email, URL, and markdown, backtracking engines on large input, regex on unbounded strings.
- **Confirms:** A crafted input of reasonable size blocks a worker or event loop for seconds. Provide input length and measured or analyzed behavior.
- **Not a finding:** Linear-time engines, length caps before matching, timeouts.

## RES-02: Parser bombs and unbounded structures

- **Hunt:** Deeply nested JSON, XML, YAML, GraphQL, and ASTs; XML entity expansion; zip and gzip decompression bombs; tar with huge entry counts; image decompression bombs and huge dimensions; PDF and office parsers; hash-collision key flooding; unbounded recursion in user-defined structures.
- **Confirms:** Small input causes disproportionate CPU, memory, or disk use.
- **Not a finding:** Streaming decompression with ratio and size limits, depth limits, parser hardening flags.

## RES-03: Unbounded work per request

- **Hunt:** No pagination limits, `expand` and `include` graph blowups, batch endpoints without size limits, N+1 amplification, report and export endpoints running synchronously, full-table scans on user filters, search with leading wildcards, user-controlled sorting on unindexed columns, GPU or model inference without budgets.
- **Confirms:** One request can occupy a worker or database for an unreasonable time or return unbounded data.
- **Not a finding:** Enforced caps, async jobs, cost-bounded queries.

## RES-04: Rate limiting and bot defense

- **Hunt:** Missing limits on login, OTP, reset, signup, search, checkout, card testing paths, and expensive endpoints; limits per IP only (shared NATs, spoofable headers); limits held in process memory behind multiple instances; limits keyed on attacker-chosen values; no layered limits (IP, account, device, card BIN); no challenge or proof-of-work for abuse; limits reset on deploy.
- **Confirms:** An attacker can brute force, enumerate, card-test, or exhaust cost without being throttled.
- **Not a finding:** Layered limits in a shared store with correct client identification.

## RES-05: Timeouts, deadlines, and cancellation

- **Hunt:** Outbound HTTP, database, and queue calls with no connect, read, or total timeouts; unbounded `await` chains; no deadline propagation or cancellation through request context; server timeouts shorter than load balancer idle timeout causing 502s; slowloris exposure; worker threads pinned by slow clients.
- **Confirms:** A slow dependency or client exhausts the connection or thread pool and takes down unrelated traffic.
- **Not a finding:** Layered timeouts with propagated deadlines.

## RES-06: Retries, backpressure, and queues

- **Hunt:** Retries without jitter, caps, or budgets (retry storms); non-idempotent retried operations; unbounded queues; poison messages without dead-letter queues; consumers that are not idempotent; no backpressure from slow downstreams; thundering herd on recovery.
- **Confirms:** A transient failure amplifies into a sustained outage or duplicate side effects.
- **Not a finding:** Bounded retries with jitter, DLQ, idempotent handlers.

## RES-07: Lock ordering, deadlocks, and starvation

- **Hunt:** Locks acquired in inconsistent orders, locks held across network calls, database transactions spanning external calls, advisory locks on pooled sessions, global locks on hot paths, unbounded lock waits.
- **Confirms:** Concurrent requests can deadlock or starve, or an attacker can hold a shared lock.
- **Not a finding:** Consistent ordering, short critical sections, lock timeouts.

## RES-08: Denial of wallet

- **Hunt:** Unbounded autoscaling, per-invocation serverless billing without limits, LLM token spend per user, SMS and email sending, image optimization, egress, transcoding, third-party API calls triggered by anonymous users, free tiers abusable by scripted signups.
- **Confirms:** An attacker or bug can create cost far above value with a simple loop. Include the unit cost if known.
- **Not a finding:** Budgets, quotas, per-tenant caps, alerts, and kill switches.

## RES-09: Blast radius and process isolation

- **Hunt:** Crash-prone or untrusted parsers and renderers running in the main server process, shared memory and temp directories across tenants, no per-tenant bulkheads, no memory ceilings, orphaned temp files, locks, or child processes after failures, shutdown that drops in-flight work.
- **Confirms:** One bad input or tenant can take down or poison others, or failure leaves stale state.
- **Not a finding:** Isolated workers with limits and deterministic cleanup in `finally` blocks.

## RES-10: Event loop and thread pool starvation

- **Hunt:** Synchronous crypto, compression, JSON parse of large bodies, sync file I/O, CPU loops in request handlers (Node), `.Result` and `.Wait()` blocking async code (.NET), thread-pool exhaustion, connection-pool exhaustion with long-held connections.
- **Confirms:** A few requests degrade the whole instance. Provide the blocking call and input.
- **Not a finding:** Work offloaded to workers or async APIs with limits.

## RES-11: Upload and request size limits

- **Hunt:** No body size limits at the proxy and the app, multipart with unlimited parts or fields, streaming uploads buffered into memory, platform body limits assumed but not enforced, unbounded header sizes, temp files never cleaned.
- **Confirms:** Large requests exhaust memory, disk, or bandwidth.
- **Not a finding:** Limits enforced at edge and application with streaming.

## RES-12: Health checks, shutdown, and failure modes

- **Hunt:** Liveness checks that call the database (cascading restarts), readiness that never fails, no graceful shutdown on SIGTERM, health endpoints leaking internals, single points of failure for auth, payments, or secrets retrieval with no documented fail-closed behavior, migrations that lock tables during deploy, overlapping instances during zero-downtime deploys running the same cron or job.
- **Confirms:** A realistic dependency failure or deploy causes outage, duplicate jobs, or fail-open security behavior.
- **Not a finding:** Documented fail-closed behavior, distributed locks or leader election for jobs, backward-compatible migrations.
