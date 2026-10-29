# The 12 Pre-Production Verification Gates

Run these in Phase 7 (or earlier as checks). Record each as `pass`, `fail`, or `not_run` with evidence or reason. A failed gate that maps to a `P0` or `P1` risk changes the release recommendation. Run active tests only against authorized staging or local environments, never production.

| # | Gate | What to prove | How |
| :--- | :--- | :--- | :--- |
| 1 | Concurrency and lock cycles | No double spend, oversell, duplicate redemption, or deadlock on checkout, balance, coupon, inventory, and refund paths | Fire parallel requests; assert invariants; run with the real database and driver (not mocks) |
| 2 | Boundary, truncation, and expiry | Empty, truncated, oversized, non-UTF-8, and expired signatures, JWTs, cookies, and links are rejected with `401`, `403`, or `422` | Boundary-value tests including clock skew edges |
| 3 | Resource, parsing, and denial of service | Nested JSON and GraphQL, pathological regex, decompression bombs, large uploads, and aborted requests keep CPU and memory bounded and cancel work | Limit and timeout tests with time budgets |
| 4 | Fatal-path isolation and cleanup | Worker crashes and timeouts leave the supervisor running and no temp files, locks, or partial records behind | Crash and timeout injection |
| 5 | Deserialization, prototype, mass assignment | `__proto__` and `constructor` payloads, unexpected fields (`role`, `price`, `tenantId`), and malformed RPC or Flight payloads are rejected | Payload corpus against each boundary |
| 6 | Privacy, consent, production config, stack profiles | Debug and test flags off; security headers and cache headers enforced; no personal data logged or sent before consent; every applicable `STK-*` check marked pass, fail, or not applicable with evidence | Inspect deployed responses; config review; log review |
| 7 | Secrets and git history | No live secrets in working tree or full history | Secret scanner across tree and history; any hit is P0 until rotated |
| 8 | CI/CD pipeline | Actions pinned to full SHAs, least-privilege `permissions`, isolated caches, no untrusted code in privileged triggers, release path gated | Workflow lint and manual review of triggers |
| 9 | Dependency and install policy | Lockfiles committed and enforced, install scripts disabled or allowlisted, advisories and known-exploited checks clean or accepted, minimum release age, SBOM generated and diffed | Package-manager audit, scanner, CI config review |
| 10 | Multi-user and multi-tenant isolation | Two-tenant and two-role matrix shows zero BOLA, BFLA, BOPLA, cache, search, and export leakage | Automated matrix against staging |
| 11 | Failure injection and fail-closed behavior | Killing dependencies, forcing timeouts, and replaying duplicate or out-of-order webhooks fail closed and roll back cleanly | Fault injection on staging |
| 12 | Operational and incident readiness | Security alerts wired and tested; secret rotation runbook; restore tested; migration rollback tested; kill switches documented; on-call owner named | Evidence links, drill results |

## `gates.json` shape (optional input to the renderer)

```json
{
  "gates": [
    { "id": 1, "status": "fail", "evidence": "tests/race/checkout.test.ts shows double redemption", "finding_ids": ["SEC-003"] },
    { "id": 7, "status": "pass", "evidence": "gitleaks v8 full history, 0 findings" },
    { "id": 12, "status": "not_run", "reason": "No staging alerting to test" }
  ]
}
```

## Recommended tooling (verify availability in the environment)

| Area | Tools |
| :--- | :--- |
| SAST and semantic analysis | Semgrep, CodeQL |
| Secret scanning (tree and history) | gitleaks, trufflehog |
| Dependencies, SBOM, posture | osv-scanner (supports many ecosystems including Dart `pubspec.lock`), `npm audit` and `npm audit signatures`, `pip-audit`, `cargo audit`, `dotnet list package --vulnerable --include-transitive`, OpenSSF Scorecard |
| Container and OS images | Trivy, Grype |
| IaC | Checkov, tfsec |
| GitHub Actions | A workflow static analyzer such as zizmor, plus manual trigger review |
| DAST (authorized staging only) | OWASP ZAP, nuclei |

Tools complement the audit; they do not replace tracing. A clean scan is evidence for a gate, not proof of absence.
