# Phase 1: Reconnaissance

Goal: understand the system well enough to know where the boundaries are, then turn that understanding into a deterministic coverage ledger that hunters can work from. No vulnerability claims are made in this phase.

Outputs, written to the output directory:

- `architecture.md`: the map (sections below).
- `coverage-ledger.json`: the work plan and later the coverage record.

## 1. Gather evidence (read, do not execute)

Run these as read-only steps. Spawn isolated agents for the larger ones if the platform supports it.

1. **Inventory.** Languages, frameworks and pinned versions (read lockfiles, not just manifests), monorepo layout, entry points, build and deploy config, environment variable names (names only, never values).
2. **Entry points and protocols.** HTTP and REST routes, GraphQL schemas and resolvers, gRPC and RPC, Server Actions and Route Handlers, WebSocket and SSE, webhooks (inbound and outbound), CLI, IPC, deep links and URL schemes, scheduled and queue workers, serverless handlers, cron endpoints.
3. **Authentication and authorization.** Identity providers, session or token format, where identity is established, where roles and tenancy are enforced, middleware and proxy layers, policy engines, service-to-service auth.
4. **Data stores and flows.** Databases and ORMs, caches, queues, search indexes, object storage, logs, analytics, third-party processors. Trace how tenant data, PII, payment data, and secrets move between them.
5. **Trust boundaries.** Internet to edge, edge to origin, app to database, service to service, browser to API, mobile to API, CI to registry, agent to tool, tenant to tenant.
6. **Pipeline and release.** CI workflows and triggers, runners, secrets and OIDC, registries, signing, update channels, IaC and deploy targets.
7. **AI surface.** Model calls, prompts, retrieval sources, tools and MCP servers, memory stores, output consumers.
8. **Reconnaissance leaks.** Committed `.env` files, source maps, backup files, debug or admin routes (`/debug`, `/actuator`, `/metrics`, GraphQL playground, Swagger), verbose banners, exposed `.git`.
9. **Prior evidence.** Earlier audits, advisories, `SECURITY.md`, dependency audit output, CI security scan results, previous `findings.json`. Treat these as leads, never as proof.
10. **Deterministic scans (if tools exist).** Secret scan of working tree and full git history, dependency audit, IaC scan, workflow lint. Record tool name, version, and result. Absence of a tool is a coverage gap, not a pass.

## 2. Write `architecture.md`

Use exactly these headings so later phases can find them.

```markdown
# Architecture: <project>

## Summary
<3 to 6 sentences: what it does, who uses it, where it runs.>

## Stack and versions
<table: component, technology, pinned version, source file>

## Stack profiles detected
<list from STACK-PROFILES.md>

## Entry points
<table: id, protocol, path or name, auth required (yes/no/unknown), handler file:line>

## Trust boundaries
<numbered list; each names the control that is supposed to enforce it and where>

## Data flows
<for each sensitive data class: where it is created, stored, cached, logged, exported, deleted>

## Identity, roles, tenancy
<how identity and tenant id reach the data layer>

## Pipeline and release
<workflows, triggers, secrets, publish path>

## AI and agent surface
<models, tools, retrieval, memory, or "none">

## Prior evidence
<what was found, what it points at>

## Scan results
<tool, version, result, or "not available">

## Out of scope
<exclusions and why>
```

Cite `file:line` for every row that names code.

## 3. Build `coverage-ledger.json`

The ledger turns the map into units of work. A unit is a bounded area one hunter can examine in depth: a route group, a module, a workflow file set, a data-access layer, an infrastructure folder.

### Unit sizing

- Aim for units a hunter can read fully (roughly 10 to 40 files or under 4,000 lines of relevant code).
- Split by trust boundary, not by directory convention. A webhook handler and its signature helper belong in one unit.
- Every entry point from `architecture.md` must appear in at least one unit.
- Every detected stack profile must have at least one unit that owns its checks.
- Add cross-cutting units: `authz-policy`, `secrets-and-config`, `ci-cd`, `dependencies`, `data-isolation`, `error-handling`, `logging-and-alerting`.

### Ledger shape

```json
{
  "schema_version": 1,
  "project": "example-shop",
  "run": 1,
  "created": "2026-10-29T00:00:00Z",
  "stack_profiles": ["nextjs", "neon", "vercel"],
  "units": [
    {
      "id": "U-001",
      "name": "Payment webhook ingress",
      "files": ["app/api/webhooks/stripe/route.ts", "lib/payments/verify.ts"],
      "entry_points": ["EP-014"],
      "domains": [1, 2, 7, 22],
      "attack_classes": ["CORE-03", "CORE-04", "WEB-09", "STK-NEXT-06"],
      "priority": "high",
      "status": "pending",
      "checks": []
    }
  ]
}
```

Field rules (enforced by `scripts/validate-coverage-ledger.cjs`):

- `id` is unique and matches `U-` followed by digits.
- `domains` are integers 1 to 30 from `DOMAIN-MATRIX.md`.
- `attack_classes` are class ids defined in the attack-class files.
- `priority` is `high`, `medium`, or `low`. Rank by reachability first (unauthenticated internet-facing is `high`), then data sensitivity, then blast radius.
- `status` is one of `pending`, `in_progress`, `checked`, `blocked`, `not_applicable`.
- `blocked` and `not_applicable` require a `reason`.
- `checks` entries record what was actually examined (see `HUNTING.md`). A unit cannot be `checked` with an empty `checks` list.

### Priority and routing

Use the routing table in `HUNTING.md` to fill `attack_classes`. Include the stack-profile classes (`STK-*`) for any unit that touches that stack. When unsure, over-assign; hunters may mark a class `not_applicable` with a reason.

## 4. Validate

Run the validator after creating the ledger and after every later update:

```
node scripts/validate-coverage-ledger.cjs coverage-ledger.json
```

Fix every error before starting Phase 2. If Node is unavailable, check the field rules above by hand and say so in `architecture.md`.

## 5. Exit criteria

- `architecture.md` has every heading filled in or marked "none".
- Every entry point maps to a unit.
- The ledger validates.
- Blockers (no sandbox, no git history, missing lockfile) are written down.
