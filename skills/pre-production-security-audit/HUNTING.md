# Phase 2: Coverage-Led Hunting

Goal: examine every ledger unit against its assigned attack classes, record named checks with evidence, and surface candidates for Phase 3. Hunters find; they do not decide verdicts.

## 1. Orchestration

1. Order units by `priority`, then by number of assigned classes.
2. Give each hunter exactly one unit (or a few small related ones) plus: `architecture.md`, the unit entry from the ledger, and the attack-class files for its assigned classes. Do not share other hunters' notes.
3. Run hunters in parallel if the platform allows, in batches sized to avoid rate limits. In Solo Mode, run them sequentially and write results to disk after each unit.
4. After each batch, the Lead merges check records into the ledger and runs `scripts/validate-coverage-ledger.cjs`.
5. Run Critics (section 4) when all `high` units are `checked`, and again when all units are done.
6. Stop hunting when the Critic finds no material gaps or two consecutive Critic rounds add no new candidates.

## 2. Routing table

Assign classes to units by what the unit touches.

| Unit touches | Assign |
| :--- | :--- |
| Any request handler, Server Action, RPC, resolver | `CORE-01`, `CORE-02`, `CORE-07`, `CORE-08`, `WEB-01`, `WEB-02`, `DATA-01` |
| SQL, ORM, NoSQL, search, shell, templates, file paths | `CORE-01` to `CORE-06` |
| Payments, orders, balances, coupons, credits, refunds | `CORE-09` to `CORE-14`, `WEB-09` |
| Webhooks and callbacks | `WEB-09`, `CORE-12`, `RES-06` |
| Login, sessions, tokens, OAuth, MFA, password reset | `WEB-03` to `WEB-08`, `CRY-01` to `CRY-04` |
| HTTP server, proxy, CORS, headers, redirects, fetchers | `WEB-10` to `WEB-18` |
| Frontend components, rendering, messaging, bundles | `CLI-01` to `CLI-10` |
| Dependencies, lockfiles, install scripts, workflows, release | `SC-01` to `SC-14` |
| IaC, containers, cloud config, serverless, ingress | `CLD-01` to `CLD-12` |
| Caches, CDN, search, exports, jobs, multi-tenant data | `DATA-01` to `DATA-10` |
| Parsers, uploads, regex, queues, retries, outbound calls | `RES-01` to `RES-12` |
| LLM calls, prompts, tools, MCP, RAG, memory | `AI-01` to `AI-12` |
| Flutter, native mobile, Electron, deep links, local IPC | `MOB-01` to `MOB-12` |
| Secrets, crypto, PII, consent, retention, logs | `CRY-01` to `CRY-12` |
| Next.js, Node.js, .NET, Neon, Azure, Render, Vercel, Flutter code or config | matching `STK-*` classes in `STACK-PROFILES.md` |

Always assign `CORE-15` (error handling and fail-open) and `DATA-01` (tenant scoping) to units that gate access.

## 3. Hunter prompt

Use this prompt, filling the placeholders. Keep it intact; the constraints are the point.

```
You are a security hunter. You have one unit to audit.

UNIT: {unit id and name}
FILES: {files}
ENTRY POINTS: {entry points}
CLASSES: {attack class ids with their text}
CONTEXT: architecture.md (attached)

Rules:
1. Read every file in the unit fully, plus any caller, callee, middleware, config, or schema
   needed to decide whether a check exists. Follow data from source to sink across files.
2. For each assigned class, record a check: what you looked at, what you concluded
   (no_issue, candidate, blocked, not_applicable), and the file:line evidence.
3. A candidate needs: attacker-controlled source, the missing or bypassable check,
   the sink, and a concrete exploit sequence. If any part is unknown, say exactly which fact
   is unknown. Do not guess.
4. Before reporting a candidate, look for the defense you may have missed: framework defaults
   in the pinned version, middleware, database constraints, input schemas, network policy,
   an upstream check. Write down what you looked for.
5. Do not run target code unless a sandbox is confirmed. Do not use real credentials.
   Never write secret values; record location and type only.
6. Do not stop at the first candidate. Finish every assigned class.
7. Defense-in-depth gaps (a second layer is absent while the first holds) are hardening notes,
   not candidates.
8. Output JSON: {"unit": id, "checks": [...], "candidates": [...], "notes": [...]}.
```

### Check record

```json
{
  "class": "CORE-03",
  "result": "no_issue",
  "evidence": ["lib/payments/verify.ts:L12-L40"],
  "note": "HMAC verified over raw body with timingSafeEqual; length checked first"
}
```

`result` is `no_issue`, `candidate`, `blocked`, or `not_applicable`. Evidence is required for `no_issue` and `candidate`. `blocked` and `not_applicable` need `note` with the reason. A `candidate` check must include `candidate_id` linking to the candidate record.

### Candidate record

```json
{
  "id": "C-007",
  "unit": "U-001",
  "title": "Stripe webhook accepts unsigned replays after 5 minute window",
  "class": "WEB-09",
  "domains": [1, 22],
  "claim": "One paragraph stating source, missing check, sink, and impact.",
  "trace": [
    {"file": "app/api/webhooks/stripe/route.ts", "line": 21, "role": "source", "note": "raw body read"},
    {"file": "lib/payments/verify.ts", "line": 33, "role": "check", "note": "timestamp tolerance only"},
    {"file": "lib/orders/fulfill.ts", "line": 58, "role": "sink", "note": "marks order paid"}
  ],
  "unknowns": ["whether the processed-event table has a UNIQUE constraint in production schema"]
}
```

## 4. Coverage critic prompt

Run Critics with the ledger and `architecture.md` only. They do not report vulnerabilities.

```
You are a coverage critic. You have the architecture map and the coverage ledger.

Find gaps, not bugs. Report:
1. Entry points or trust boundaries with no unit or only shallow checks.
2. Units marked checked whose checks are generic, lack file:line evidence, or skip assigned classes.
3. Attack classes that should apply to a unit but were not assigned.
4. Stack-profile checks (STK-*) with no owner.
5. Transport or routing variants not considered (alternate paths, methods, content types,
   locales, prefetch or data routes, versioned APIs, internal or admin duplicates).
6. Cross-unit flows nobody owns (data written in one unit and read unsafely in another).
7. Blocked units whose blocker could be removed.

Output JSON: {"gaps": [{"unit_or_area": "...", "reason": "...", "suggested_classes": [...],
"suggested_files": [...]}]}.
```

The Lead turns each gap into a new or reopened unit and returns to step 1.

## 5. Methodology notes for hunters

- **Trace, do not pattern-match.** A string-concatenated query is only a finding if attacker input reaches it unvalidated and unparameterized. Follow the variable.
- **Check every variant.** For each protected resource, enumerate the routes, methods, content types, transports, and framework-internal paths that reach it. Authorization that exists on one variant and not another is the most common real finding.
- **Authorization lives at the data layer.** Prefer finding the check closest to the query. A check only in middleware, a proxy, a route guard, or the UI is a candidate until every variant is proven covered.
- **Read the lockfile.** Behavior depends on the pinned framework version. Note advisories for the exact version, and re-check the advisory list for that package at audit time.
- **Follow money, identity, and state.** Anything that moves value, changes who someone is, or advances a state machine deserves a concurrency and replay check.
- **Look for the obvious.** Hardcoded credentials, debug flags, default passwords, open admin routes, disabled TLS verification, `*` CORS with credentials, public buckets. Check them before the exotic.
- **Wildcard pass.** After assigned classes, spend a bounded effort on "what would a motivated attacker try here that no class names?" Record it as a check with class `CORE-16`.
- **Test fixtures and mocks.** Findings in test-only code are not vulnerabilities unless that code ships or is reachable in production.
- **Stop at proof.** When a candidate is traced end to end, record it and move on. Phase 3 will challenge it.

## 6. Exit criteria

- No unit is `pending` or `in_progress`.
- Each `checked` unit has at least one check per assigned class.
- Critics found no material gaps in the last round.
- Candidates are saved under `candidates/` as one JSON file per candidate.
