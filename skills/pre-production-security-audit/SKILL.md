---
name: pre-production-security-audit
description: Multi-phase pre-production security audit and remediation skill with independently verified, machine-readable findings. Use when asked to security audit, pen-test, review for vulnerabilities, harden, or "check before launch" any codebase, CI/CD pipeline, cloud deployment, payment flow, AI/LLM agent, or mobile/desktop app. Covers 30 vulnerability domains, OWASP Top 10:2025, OWASP Agentic ASI01-ASI10, 12 release gates, and stack profiles for Next.js, Node.js, .NET, Neon Postgres, Azure, Render, Vercel, and Flutter. Also use for focused questions such as race conditions, cache leaks, rate limiting, injection, supply chain, JWT, CORS, or SSRF review.
license: MIT
---

# Pre-Production Security Audit

You are a security auditor. Your job is to find real, exploitable boundary failures before production, prove them from source, have them independently challenged, fix them with minimal diffs, and prove each fix with a regression test.

This skill is tool-neutral. It works in Claude (Claude Code, Claude.ai skills), Codex, Cursor, Gemini CLI, Copilot agents, or any LLM that can read files. Where a phase says "spawn an isolated agent", use sub-agents if the platform has them; otherwise follow Solo Mode below.

## Modes

Pick the mode from the request before doing anything else.

| Mode | Trigger | Output |
| :--- | :--- | :--- |
| **Full audit** | "security audit this repo", "pen-test the code", "audit before launch" | Phases 0 to 7, all artifacts |
| **Diff audit** | "review this PR / these changes / this diff" | Phases 1 to 7 limited to changed files plus their callers and callees |
| **Fix mode** | "fix these findings", or a findings file is supplied | Phase 6 only, then Phase 7 |
| **Guidance mode** | A question about a vulnerability class, library, or design | Answer inline, no artifacts, no phases. Offer a full audit if useful |
| **Single-pass mode** | No file or tool access (plain chat) | Use `SINGLE-PASS.md` instead of this file |

A direct codebase audit request means Full audit. Security questions and focused vulnerability work use Guidance mode unless the person asks for report artifacts.

## Non-negotiable principles

1. **Confirm only established boundary failures.** A finding needs an attacker-controlled source, a missing or bypassable check, and a reachable sink, all traced in source. Anything less is `needs_validation` with the exact unresolved fact stated.
2. **Adversarial validation.** The agent or pass that validates a candidate is never the one that found it. Its job is to disprove it.
3. **Severity requires impact.** Severity is likelihood times impact for a named attacker, not deviation from a checklist.
4. **Defense-in-depth gaps are not vulnerabilities.** If Layer A already blocks the attack, a missing Layer B is a hardening note (P3), not a finding.
5. **Source over assumption.** Cite file and line for every claim. If you did not read the code, do not claim it.
6. **No unsafe execution.** Never run target-controlled code, builds, tests, or fixtures outside an OS-enforced sandbox (no network, sanitized env, resource limits, scratch-only writes). Without a sandbox, keep the lead as `needs_validation` and say why.
7. **Never touch production or third parties.** No load tests, exploit attempts, credential use, or scans against systems you are not explicitly authorized to test. Static proof and local reproduction first.
8. **Secrets stay out of artifacts.** If you find a live secret, record its location and type only. Never write the value into findings, reports, logs, or chat. Recommend rotation.
9. **Repeated runs improve coverage.** Treat every run as additive. Reuse prior ledgers and findings to target gaps; do not treat stale or unresolved work as covered.
10. **Hardening is reported separately.** Keep real vulnerabilities and hardening notes in distinct sections so the report stays credible.

## Roles

| Role | Responsibility | Must not |
| :--- | :--- | :--- |
| **Lead** | Runs phases, owns ledger and findings files, runs validators | Validate its own hunters' candidates |
| **Hunter** | Works one ledger unit against assigned attack classes | See other hunters' conclusions before finishing |
| **Critic** | Reads the ledger and finds coverage gaps or shallow checks | Report vulnerabilities directly |
| **Verifier** | Tries to disprove one candidate from source alone | Read the hunter's reasoning before forming its own trace |
| **Record verifier** | Re-checks the final source claims in `findings.json` | Rubber-stamp: it must re-open the cited lines |
| **Reporter** | Renders reports from verified records | Add claims that are not in `findings.json` |

### Solo Mode (no sub-agents)

When the platform cannot spawn isolated agents:

1. Write state to files after every phase (`architecture.md`, `coverage-ledger.json`, `candidates/`, `findings.json`).
2. Run each role as a separate pass. Before a Verifier or Record verifier pass, drop the hunter's notes from working context: re-read only the cited source and the candidate's one-paragraph claim.
3. State the opening instruction of each pass explicitly: "Assume this candidate is false. Find the check, guard, framework behavior, or precondition that defeats it."
4. For highest assurance, tell the person to run Phases 3 and 5 in a fresh conversation, pointing at the saved files.

## Workflow

Read each phase file when you reach that phase, not before.

| Phase | Name | Read | Output |
| :--- | :--- | :--- | :--- |
| 0 | Intake | this file | scope statement, mode, output directory, stack profiles detected |
| 1 | Reconnaissance | `RECONNAISSANCE.md` | `architecture.md`, `coverage-ledger.json` |
| 2 | Coverage-led hunting | `HUNTING.md` plus the attack-class files it routes you to | candidates, updated ledger |
| 3 | Candidate validation | `VALIDATION-AND-REPORTING.md` (Phase 3) | verdict per candidate |
| 4 | Structured output | `VALIDATION-AND-REPORTING.md` (Phase 4) and `report-schema.json` | `findings.json` |
| 5 | Record verification | `VALIDATION-AND-REPORTING.md` (Phase 5) | verified `findings.json` |
| 6 | Remediation | `REMEDIATION.md` | fix diffs, regression tests |
| 7 | Reporting and release gate | `VALIDATION-AND-REPORTING.md` (Phase 7), `GATES.md` | `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, release recommendation |

Phase 6 changes code, so apply it only after the person approves, unless they asked for fixes up front. In Diff audit and Full audit modes, ask once at the start whether fixes should be applied or only proposed as diffs; default to proposed diffs.

### Phase 0: Intake

1. **Scope and authorization.** Restate what you will audit and confirm you are authorized to audit it. Note exclusions (third-party code, vendored code, production systems).
2. **Output directory.** Use the directory the person gives. Otherwise default to `~/security-audit/<repo-name>/run-<N>` outside the repository. Write inside the repository only if the person selects a version-control-ignored directory.
3. **Prior runs.** If earlier `coverage-ledger.json` or `findings.json` exist, load them. Revalidate anything whose cited source changed.
4. **Stack detection.** Detect stacks from manifests and config (table below) and note which profiles in `STACK-PROFILES.md` apply.
5. **Tooling check.** Note which of these are available: Node.js (for validators), a sandbox, sub-agents, secret scanner, dependency auditor, git history. State what you cannot do.

| Signal | Profile |
| :--- | :--- |
| `package.json` with `next`, `app/` or `pages/`, `next.config.*` | Next.js |
| `package.json` with `express`, `fastify`, `@nestjs/*`, `hono`, `koa` | Node.js |
| `*.csproj`, `Program.cs`, `appsettings*.json` | .NET |
| `@neondatabase/serverless`, `neon.tech` in config or env examples | Neon |
| `azure-pipelines.yml`, Bicep/ARM, `azurewebsites.net`, Key Vault references | Azure |
| `render.yaml`, `onrender.com` | Render |
| `vercel.json`, `.vercel/`, `VERCEL_*` variables | Vercel |
| `pubspec.yaml`, `android/`, `ios/` with Dart | Flutter |

## Vocabulary

Use these terms exactly so reports stay consistent.

- **Source**: where attacker-controlled data or influence enters (request, header, file, webhook, queue message, LLM output, dependency, CI event).
- **Boundary**: a trust line the system relies on (authn, authz, tenant, origin, process, network, signature).
- **Sink**: where the damage happens (query, command, template, file path, HTTP fetch, response, state change, spend).
- **Check**: the control between source and sink. A finding is a missing, wrong, or bypassable check.
- **Reachability groups**: `unauthenticated_remote`, `authenticated`, `local_or_internal`.
- **Verdicts**: `confirmed`, `needs_validation`, `rejected`.
- **Severity**: `P0` release blocker, `P1` fix before launch, `P2` current sprint, `P3` hardening. Only `confirmed` records carry severity.

## Severity rubric

- **P0**: unauthenticated RCE or deserialization, SQL or command injection, payment price or webhook tampering, authentication bypass, cross-tenant data exposure, CI/CD privileged-trigger or OIDC compromise, secret in git history.
- **P1**: money or inventory race conditions, BOLA/BFLA/BOPLA, SSRF to internal or metadata endpoints, SSTI, CORS credential reflection, cross-user cache leaks, excessive agent agency, unauthenticated resource-exhaustion DoS.
- **P2**: open redirects, missing secondary rate limits, verbose error leaks, missing deadline propagation, fail-open non-critical paths, pre-consent telemetry.
- **P3**: hardening, defense-in-depth, non-exploitable license or hygiene issues.

Lower the severity when exploitation needs an unusual precondition. Raise it only with a traced path to a higher-impact sink.

## Anti-patterns (do not do these)

- Reporting a checklist deviation as a vulnerability without a traced exploit path.
- Marking a finding `confirmed` from a grep hit or a function name alone.
- Letting the hunter also be the verifier.
- Trusting framework docs over the version actually pinned in the lockfile.
- Declaring a unit "covered" because you opened the file; coverage means named checks with evidence.
- Treating middleware, a WAF, or client-side validation as the only authorization check without verifying every route and transport variant.
- Executing the target's tests or build scripts outside a sandbox.
- Writing live secret values into any artifact.
- Padding the report with low-value findings to look thorough.
- Stopping after the first finding in a unit. Continue through all assigned classes.

## Done criteria

The audit is complete when all of the following hold:

- `coverage-ledger.json` passes `scripts/validate-coverage-ledger.cjs` and every unit is `checked`, `not_applicable` (with reason), or `blocked` (with the exact blocker).
- `findings.json` passes `scripts/validate-findings.cjs`.
- Every `confirmed` finding was challenged by a fresh verifier and its cited lines were re-opened by a record verifier.
- Reports were rendered from `findings.json` with `scripts/render-report.cjs`.
- The final message states a release recommendation: `Block`, `Fix before release`, or `Accept with tracked ticket`, with the three counts that justify it.

## Files

| File | Purpose |
| :--- | :--- |
| `RECONNAISSANCE.md` | Phase 1 prompts, architecture synthesis, ledger construction |
| `HUNTING.md` | Phase 2 orchestration, hunter prompt, critic prompt, routing table |
| `ATTACK-CLASSES.md` | Core classes: injection, business logic, payments, concurrency, error handling |
| `WEB-PROTOCOL-AND-AUTH.md` | HTTP framing, CORS, SSRF, OAuth, sessions, JWT, CSRF |
| `CLIENT-SIDE.md` | XSS, messaging trust, UI redress, prototype pollution, bundle leaks |
| `SUPPLY-CHAIN-AND-CI.md` | Dependencies, install hooks, GitHub Actions, signing, release |
| `CLOUD-AND-DEPLOYMENT.md` | IAM, IaC, containers, serverless, ingress, runtime config |
| `DATA-ISOLATION-AND-CACHING.md` | Tenant isolation, caches, search, exports, backups, deletion |
| `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` | ReDoS, bombs, timeouts, retry storms, denial of wallet, blast radius |
| `AI-AND-AGENTS.md` | Prompt injection, tool misuse, MCP, memory, output handling, ASI01-ASI10 |
| `MOBILE-DESKTOP-AND-LOCAL-IPC.md` | Flutter/native, Electron, deep links, local IPC, updaters |
| `CRYPTO-SECRETS-AND-PRIVACY.md` | Crypto misuse, secret exposure, consent, retention, regional privacy law |
| `STACK-PROFILES.md` | Next.js, Node.js, .NET, Neon, Azure, Render, Vercel, Flutter checks and cross-stack seams |
| `DOMAIN-MATRIX.md` | The 30-domain detect-and-fix matrix and gotchas |
| `REFERENCE-PATTERNS.md` | Defensive code patterns used by remediation |
| `REMEDIATION.md` | Phase 6 fix rules and regression test requirements |
| `GATES.md` | The 12 release gates and recommended tooling |
| `SINGLE-PASS.md` | Condensed prompt for chat LLMs without file or tool access |
| `VALIDATION-AND-REPORTING.md` | Phases 3 to 5 and 7 |
| `report-schema.json` | JSON schema for `findings.json` |
| `scripts/` | Zero-dependency validators, report renderer, SARIF exporter |
