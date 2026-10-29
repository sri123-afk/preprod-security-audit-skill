# Reference Defensive Patterns

Use these when remediating. They are language-aware sketches: adapt names and imports to the project, keep the security property, and add a regression test. Placeholders (`verifySession`, `HttpError`, `db`) stand for project code.

## Pattern 1: Constant-time signature and buffer-safe verification (Domains 1, 7, 24)

```python
import hmac
import hashlib

def verify_signed_payload(raw_bytes: bytes, provided_sig_hex: str, secret_key: bytes) -> bool:
    if not raw_bytes or not provided_sig_hex or len(provided_sig_hex) != 64:
        return False
    try:
        provided_sig_bytes = bytes.fromhex(provided_sig_hex)
    except ValueError:
        return False
    expected_sig_bytes = hmac.new(secret_key, raw_bytes, hashlib.sha256).digest()
    if len(provided_sig_bytes) != len(expected_sig_bytes):
        return False
    return hmac.compare_digest(expected_sig_bytes, provided_sig_bytes)
```

Notes: verify over the raw bytes, decode the signature to bytes before comparing, check lengths first, compare in constant time, then enforce a timestamp tolerance and store a processed-event id.

## Pattern 2: Scoped cache keys with fail-closed behavior (Domains 15, 19, 21)

```typescript
export function buildTenantCacheKey(ctx: { tenantId: string; userId: string; role: string; currency: string }, resource: string, id: string): string {
  if (!ctx.tenantId || !ctx.userId || !ctx.role) {
    throw new Error("Fail-closed: missing security context for cache key generation");
  }
  const encode = (val: string) => encodeURIComponent(val.normalize("NFKC"));
  return `v1:t=${encode(ctx.tenantId)}:u=${encode(ctx.userId)}:r=${encode(ctx.role)}:c=${encode(ctx.currency)}:${encode(resource)}:${encode(id)}`;
}
```

Notes: every cache read and write goes through this helper. Pair it with `Cache-Control: private, no-store` on personalized HTTP responses.

## Pattern 3: Fatal-path process isolation and deterministic cleanup (Domains 3, 5, 26)

```javascript
import { fork } from "node:child_process";
import { rm } from "node:fs/promises";

export async function runIsolatedWorker(workerScript, payload, tempDir, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const child = fork(workerScript, [], {
      execArgv: ["--max-old-space-size=128"],
      stdio: "ignore",
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Worker timed out and was terminated"));
    }, timeoutMs);
    child.on("message", (result) => {
      clearTimeout(timer);
      child.kill();
      resolve(result);
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`Isolated worker exited with code ${code}`));
    });
    child.send(payload);
  }).finally(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true }).catch(() => {});
  });
}
```

Notes: run native parsers, media tools, and untrusted renderers in children with memory ceilings and timeouts. Cleanup lives in `finally`.

## Pattern 4: Next.js data access layer with authorization at the data boundary (Domains 19, 20)

```typescript
import "server-only";
import { cache } from "react";
import { cookies } from "next/headers";
import { z } from "zod";

// Request-scoped memoization; never caches across users.
export const requireSession = cache(async () => {
  const token = (await cookies()).get("__Host-session")?.value;
  const session = token ? await verifySession(token) : null; // signature, expiry, revocation
  if (!session) throw new HttpError(401);
  return session;
});

const UpdateNote = z
  .object({ orderId: z.string().uuid(), note: z.string().max(500) })
  .strict();

export async function updateOrderNote(input: unknown) {
  const session = await requireSession();
  const { orderId, note } = UpdateNote.parse(input);
  const rows = await db
    .update(orders)
    .set({ note })
    .where(and(eq(orders.id, orderId), eq(orders.tenantId, session.tenantId), eq(orders.userId, session.userId)))
    .returning({ id: orders.id });
  if (rows.length === 0) throw new HttpError(404); // do not reveal existence
  return { ok: true };
}
```

Call `updateOrderNote` from the Server Action. Middleware may redirect unauthenticated users for convenience, but this function is the control.

## Pattern 5: Tenant-scoped transaction for pooled Postgres with row-level security (Domains 2, 19)

```typescript
import { Pool, type PoolClient } from "@neondatabase/serverless";

// Pooled endpoint, least-privilege non-owner runtime role.
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function withTenant<T>(tenantId: string, fn: (c: PoolClient) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)) {
    throw new Error("Fail-closed: invalid tenant id");
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]); // true = transaction-local
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
```

```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orders
  USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
-- The runtime role must not own the table and must not have BYPASSRLS.
```

A missing or empty tenant setting yields no rows rather than all rows.

## Pattern 6: ASP.NET Core default-deny and ownership-scoped writes (Domains 19, 20)

```csharp
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

app.MapPut("/orders/{id:guid}", async (Guid id, UpdateOrderDto dto, ClaimsPrincipal user,
                                        AppDb db, CancellationToken ct) =>
{
    var userId = user.GetRequiredUserId(); // project helper; reads a validated claim
    var updated = await db.Orders
        .Where(o => o.Id == id && o.OwnerId == userId)   // ownership in the predicate
        .ExecuteUpdateAsync(s => s.SetProperty(o => o.Note, dto.Note), ct);
    return updated == 0 ? Results.NotFound() : Results.NoContent();
});

public sealed record UpdateOrderDto([property: MaxLength(500)] string Note); // DTO, never the entity
```

Add `UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow` to the JSON options and validate DTOs explicitly.

## Pattern 7: Next.js webhook route with raw-body verification and idempotency (Domains 1, 7, 22)

```typescript
import { NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "node:crypto";

export const runtime = "nodejs"; // not edge: needs Node crypto

export async function POST(req: Request) {
  const raw = await req.text(); // raw bytes as text, before any JSON parsing
  const sig = req.headers.get("x-signature") ?? "";
  const ts = Number(req.headers.get("x-timestamp"));
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return new NextResponse(null, { status: 400 });

  const expected = createHmac("sha256", process.env.WEBHOOK_SECRET!).update(`${ts}.${raw}`).digest();
  let provided: Buffer;
  try { provided = Buffer.from(sig, "hex"); } catch { return new NextResponse(null, { status: 400 }); }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return new NextResponse(null, { status: 401 });
  }

  const event = JSON.parse(raw);
  // INSERT INTO processed_events(id) ... ON CONFLICT DO NOTHING; skip if already present (same transaction as the effect)
  return NextResponse.json({ ok: true });
}
```

## Pattern 8: Least-privilege, SHA-pinned GitHub Actions workflow (Domains 16, 17)

```yaml
name: ci
on:
  pull_request:          # unprivileged: no secrets for forks
permissions:
  contents: read         # default deny; grant per job
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@<full-40-char-commit-sha>
        with:
          persist-credentials: false
      - uses: actions/setup-node@<full-40-char-commit-sha>
        with:
          node-version-file: .nvmrc
      - run: npm ci --ignore-scripts
      - run: npm test
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}   # pass untrusted values via env, never inline in run:
```

Release workflows live in a separate file triggered only by protected tags or a protected environment, with `id-token: write` granted to the single job that publishes, and never run code from pull requests.

## Pattern 9: Layered rate limiting with a shared store (Domains 12, 20)

```typescript
// Pseudocode: enforce several independent limits; any one tripping denies.
const keys = [
  `ip:${verifiedClientIp(req)}`,
  `acct:${normalizedIdentifier(body.email)}`,
  `dev:${deviceId ?? "none"}`,
];
for (const k of keys) {
  const { allowed } = await limiter.consume(k, { points: 5, windowSeconds: 900 }); // shared store (Redis), not process memory
  if (!allowed) return deny(429, { retryAfter });
}
```

Add a challenge or proof of work after repeated failures, alert on spikes, and use uniform error responses so limits do not become an oracle.
