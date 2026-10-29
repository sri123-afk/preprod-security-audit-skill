# Phase 6: Remediation

Goal: fix each confirmed finding at its root cause with the smallest safe change, and prove the fix with a regression test that fails before and passes after.

Apply Phase 6 only after the person approves changes (or asked for fixes up front). Otherwise produce diffs and tests as proposals inside `findings.json`.

## Rules

1. **Root cause, not symptom.** Fix the missing check where the data is accessed, not at one entry point. After fixing, search for every sibling route, method, content type, version, and job that reaches the same sink, and fix or test each.
2. **Smallest safe diff.** No refactors, no formatting churn, no dependency swaps unless the finding requires it.
3. **Preserve behavior.** Keep documented behavior for legitimate callers. If the fix changes an API contract, say so in `residual_risk` and the report.
4. **Fail closed.** New checks deny on error, timeout, or missing context.
5. **Use project conventions.** Match the language, framework, logging, and test style already in the repository.
6. **Prefer platform controls.** Use the framework's authorization, validation, and parameterization features over hand-rolled ones. See `REFERENCE-PATTERNS.md`.
7. **Secrets: rotate, do not just remove.** Removing a secret from code or history does not revoke it. Provide rotation steps and mark the finding resolved only after rotation is confirmed by the person.
8. **No destructive history rewrites** unless the person asks. Recommend, explain the cost, and let them decide.
9. **One finding per change set** where practical, so each diff is reviewable and revertable.

## Regression test requirements

Every fixed finding gets a test that:

- Reproduces the exploit scenario from the record (the request, input, or interleaving).
- **Fails on the unfixed code and passes on the fixed code.** Run it both ways when a sandbox and test runner are available. If you cannot run it, set `regression_test.status` to `written` and say it was not executed.
- Lives in the repository's existing test layout and runs in CI.
- Covers the variants you found (other routes, methods, tenants, roles).

Test patterns by class:

| Class | Test shape |
| :--- | :--- |
| BOLA, tenant isolation | Two tenants, two roles; every endpoint returns 403 or 404 for foreign ids; includes search, export, and cache paths |
| Race conditions | Fire N parallel requests against the same resource; assert final state invariants (balance, stock, redemption count) |
| Signature and replay | Truncated, empty, wrong-length, re-encoded, expired, replayed inputs all rejected; valid input accepted once |
| Injection | Hostile payload corpus returns validation error or is stored inert; no behavior change |
| SSRF | Private, link-local, metadata, IPv6, redirect, and rebinding targets blocked |
| Cache leakage | Request as user A then user B against the deployed edge; assert no shared body and correct `Cache-Control` |
| Fail-open | Force dependency timeout and exceptions in the guard; assert deny |
| Resource exhaustion | Oversized, deeply nested, and pathological inputs return a bounded error within a time limit |
| CI and supply chain | Workflow lint passes; policy test asserts pinned SHAs, permissions, and no privileged fork execution |

## Fix verification

After applying fixes:

1. Run the project's test suite and the new regression tests (sandboxed if they execute target code).
2. Re-run the relevant scanner (secrets, dependency audit, workflow lint, IaC scan).
3. Re-open the original `source_trace` lines and confirm the check now sits between source and sink.
4. Update the finding: `fix.status` to `applied`, `regression_test.status` to `verified` (or `written`), and keep the verdict `confirmed`. Add a note in `residual_risk`.
5. Re-run `scripts/validate-findings.cjs`.

## Hardening changes

For P3 hardening notes, apply only when the person asks. Group them into one change set and keep them out of the vulnerability narrative.

## Emergency path (P0 in a deployed system)

If a confirmed P0 affects a live system, say so first, before any other output, with the immediate containment steps: disable or restrict the affected route or feature, rotate exposed secrets, apply a temporary edge rule, and then the permanent fix. State that containment is not the fix.
