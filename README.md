# pre-production-security-audit

A skill that turns a coding agent (or any capable LLM) into a pre-production security auditor. It maps a system, hunts for vulnerabilities against 30 domains and 188 attack classes and stack checks, has every candidate independently challenged, records results as machine-readable findings, fixes confirmed issues with regression tests, and ends with a release recommendation: `Block`, `Fix before release`, or `Accept with tracked ticket`.

It is tool-neutral. It works as a Claude skill, and the same files work with Codex, Cursor, Gemini CLI, Copilot agents, and any LLM that can read files. For plain chat with no file access there is a single-prompt version.

The multi-phase, adversarially validated approach is inspired by public work on agent-driven vulnerability discovery, including Cloudflare's `security-audit-skill`. The content here is independent: its own domains, attack classes, stack profiles, remediation phase, release gates, and tooling.

## What it does

Seven phases, each with its own instructions loaded only when needed:

| Phase | Name | Result |
| :--- | :--- | :--- |
| 0 | Intake | Scope, authorization, mode, stack profiles detected |
| 1 | Reconnaissance | `architecture.md` and a `coverage-ledger.json` work plan |
| 2 | Coverage-led hunting | Isolated hunters work ledger units against assigned attack classes; critics find coverage gaps |
| 3 | Candidate validation | A fresh verifier tries to disprove each candidate |
| 4 | Structured output | `findings.json` with `confirmed`, `needs_validation`, and `rejected` records |
| 5 | Independent record verification | Fresh agents re-open every cited line and re-check the claims |
| 6 | Remediation | Minimal fix diffs and regression tests that fail before and pass after |
| 7 | Reporting and release gate | `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, 12 gates, optional SARIF |

Verdicts are distinct. `confirmed` has a complete source trace and a bounded result. `needs_validation` names the exact unresolved fact and carries no severity. `rejected` records a disproved lead so later runs do not repeat it.

## What is different

- **Fix, not just find.** Phase 6 produces root-cause fixes with regression tests for every confirmed finding.
- **Release gates.** Twelve pre-production gates (concurrency, boundaries, resource limits, isolation, secrets, CI, dependencies, tenant isolation, failure injection, operational readiness) feed the release recommendation.
- **Stack profiles.** Checks for Next.js, Node.js, ASP.NET Core, Neon Postgres, Azure, Render, Vercel, and Flutter, plus cross-stack seams (shared-platform wildcards, service-to-service auth, forwarded headers, environment chains).
- **Modern threats.** OWASP Top 10:2025, the OWASP Top 10 for Agentic Applications 2026, CI/CD and registry-worm tactics, framework deserialization and middleware bypass classes, cache and tenant-isolation bugs, concurrency and denial-of-wallet classes.
- **Works without sub-agents.** Solo Mode separates roles across passes and recommends a fresh conversation for validation.
- **Deterministic artifacts.** Zero-dependency Node.js scripts validate the ledger and findings, render reports from records, and export SARIF.

## Files

All skill files live in `skills/pre-production-security-audit/`.

| File | Purpose |
| :--- | :--- |
| `SKILL.md` | Modes, principles, roles, workflow, severity rubric, anti-patterns, done criteria |
| `RECONNAISSANCE.md` | Phase 1 evidence gathering, `architecture.md` template, ledger construction |
| `HUNTING.md` | Phase 2 orchestration, routing table, hunter and critic prompts |
| `ATTACK-CLASSES.md` | Core classes: injection, signatures, access control, money, races, replay, fail-open |
| `WEB-PROTOCOL-AND-AUTH.md` | Routing variants, OAuth, sessions, JWT, CSRF, webhooks, smuggling, CORS, SSRF, GraphQL |
| `CLIENT-SIDE.md` | XSS, messaging trust, clickjacking, prototype pollution, bundle secrets |
| `SUPPLY-CHAIN-AND-CI.md` | Install hooks, malicious packages, GitHub Actions, tokens, signing, update channels |
| `CLOUD-AND-DEPLOYMENT.md` | IAM, network exposure, storage, metadata, containers, serverless, environments, logging |
| `DATA-ISOLATION-AND-CACHING.md` | Tenant scoping, row-level security, CDN and app caches, search, exports, deletion |
| `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` | ReDoS, bombs, timeouts, retries, locks, denial of wallet, blast radius |
| `AI-AND-AGENTS.md` | Prompt injection, tool permissions, MCP, memory, output handling, ASI01 to ASI10 |
| `MOBILE-DESKTOP-AND-LOCAL-IPC.md` | Mobile and Flutter, Electron, deep links, local IPC, updaters |
| `CRYPTO-SECRETS-AND-PRIVACY.md` | Randomness, encryption, signing, secrets, consent, retention, regional law |
| `STACK-PROFILES.md` | Per-stack checks and cross-stack seams |
| `DOMAIN-MATRIX.md` | The 30-domain detect-and-fix matrix and gotchas |
| `REFERENCE-PATTERNS.md` | Defensive code patterns used during remediation |
| `REMEDIATION.md` | Phase 6 rules and regression test requirements |
| `GATES.md` | The 12 release gates and recommended tooling |
| `VALIDATION-AND-REPORTING.md` | Phases 3 to 5 and 7 |
| `SINGLE-PASS.md` | Condensed prompt for chat LLMs without file access |
| `report-schema.json` | JSON Schema for `findings.json` |
| `scripts/` | `validate-findings.cjs`, `validate-coverage-ledger.cjs`, `render-report.cjs`, `to-sarif.cjs` |
| `tests/` | Tests and fixtures for the scripts |

## Installation

### Claude Code

Copy the skill folder into your skills directory.

```
# project level
mkdir -p .claude/skills
cp -r skills/pre-production-security-audit .claude/skills/

# user level
mkdir -p ~/.claude/skills
cp -r skills/pre-production-security-audit ~/.claude/skills/
```

### Claude.ai and the Claude apps

Zip the `pre-production-security-audit` folder (the folder itself at the top of the zip) and upload it in the Skills section of your settings. Skills run with code execution enabled, which the validators use.

### Skills CLI

If you publish this repository with the `skills/<name>/` layout, the Skills CLI can install it:

```
npx skills add https://github.com/sri123-afk/preprod-security-audit-skill --skill pre-production-security-audit
```

Add `--global` for a user-level install. Run `npx skills --help` for agent selection options.

### Codex, Cursor, Gemini CLI, Copilot agents, and others

Copy `AGENTS.md` to the root of the project you want to audit (or merge it into your existing agent instructions) and place the skill folder in the repository or a known path, then adjust the path in `AGENTS.md`. For tools that use a different instruction file name, copy the contents of `AGENTS.md` into it.

### Any chat LLM without file access

Paste `skills/pre-production-security-audit/SINGLE-PASS.md` as the system or first message, then paste the code, configuration, or diff you want reviewed. For larger systems, audit in slices (auth, payments, data layer, pipeline) and ask for a combined summary at the end.

## Usage

Start your agent in, or pointed at, the codebase. Examples:

```
security audit this codebase
```

```
audit this repo before launch and propose fixes
```

```
review this pull request for vulnerabilities
```

```
check the checkout flow for race conditions and price tampering
```

```
audit our GitHub Actions workflows and dependencies for supply chain risk
```

```
security audit this codebase, output to ~/audits/my-project
```

A direct codebase audit request runs full audit mode. Questions about a vulnerability class run in guidance mode with no artifacts. By default fixes are proposed as diffs; say "apply the fixes" to let the agent change code. The default output directory is `~/security-audit/<repo-name>/run-<N>`, outside the repository.

## Artifacts and scripts

```
node scripts/validate-coverage-ledger.cjs coverage-ledger.json [--complete]
node scripts/validate-findings.cjs findings.json [--final]
node scripts/render-report.cjs findings.json --ledger coverage-ledger.json --gates gates.json --out .
node scripts/to-sarif.cjs findings.json > findings.sarif
```

Scripts need Node.js 18 or later and no packages. Run the tests with `npm test`.

## Requirements

- A coding agent with tool use. Parallel sub-agents are recommended; Solo Mode covers agents without them.
- Node.js for the validators and renderer (the audit still works without it; validate by hand against the rules in the phase files).
- An OS-enforced sandbox for any target-controlled builds, tests, or fixtures: no external network, sanitized environment, resource limits, writes only to scratch paths. Without a sandbox the skill keeps the lead as `needs_validation` instead of executing target code.

## Design principles

- **Only confirm established boundary failures.** Source, missing or bypassable check, reachable sink, all traced.
- **Adversarial validation.** The pass that validates is never the pass that found.
- **Severity requires impact.** Likelihood times impact for a named attacker, not deviation from a checklist.
- **Defense-in-depth gaps are hardening notes**, reported separately.
- **Authorization belongs at the data layer.** Middleware, proxies, and UI checks are not trusted alone.
- **Secrets never enter artifacts.** Location and type only; rotate on exposure.
- **Repeated runs improve coverage.** Each run reuses earlier ledgers and findings.

## Limits and honesty

This is an aid for reviewers, not a guarantee. It can miss vulnerabilities and can be wrong. Version-specific facts (framework defaults, advisories, patch levels) change; the skill tells the agent to check the pinned version and the current advisory list at audit time. Compliance items describe engineering risk, not legal advice; involve counsel for legal conclusions. Only audit systems you own or are authorized to test.

## Contributing

See `CONTRIBUTING.md`. New attack classes must include a "Not a finding" line to protect against false positives.

## License

MIT. See `LICENSE`.
