# Phases 3 to 5 and 7: Validation, Records, Verification, Reporting

Phase 6 (remediation) lives in `REMEDIATION.md`.

## Phase 3: Candidate validation

Every unique candidate goes to a fresh Verifier. Deduplicate first: merge candidates with the same root cause and sink, keeping all affected locations.

### Verifier prompt

```
You are a security verifier. Your job is to DISPROVE this candidate.

CANDIDATE: {claim, class, domains}
CITED SOURCE: {files and line ranges only}
CONTEXT: architecture.md

Rules:
1. Form your own trace from source to sink by reading the code. Do not rely on the hunter's reasoning.
2. Actively look for what defeats it: framework defaults in the pinned version, middleware,
   validation schemas, database constraints and row-level security, network policy, upstream
   checks, feature flags, dead code, test-only paths, unreachable branches.
3. Check variants: if a check exists on one path, is there a path without it?
4. Do not execute target code unless a sandbox is confirmed. Do not use real credentials.
5. Decide one verdict:
   - confirmed: complete source trace, attacker-controlled source, missing or bypassable check,
     reachable sink, bounded observed or derivable result. State the exact request or input.
   - needs_validation: a specific fact you could not establish. State the exact fact and how to
     establish it (a config value, a deployed header, a runtime version, a schema).
   - rejected: you found the defense or the path is unreachable. Cite it.
6. For confirmed, assign severity using the rubric in SKILL.md, reachability, CWE, and OWASP 2025.
7. Output JSON: {"candidate": id, "verdict": "...", "severity": "...", "reachability": "...",
   "trace": [...], "reasoning": "...", "unresolved_fact": "...", "rejection_reason": "..."}.
```

### Verdict rules

- `confirmed` needs all of: source, missing or bypassable check, sink, impact, and either an exact exploit sequence or a derivation from code that a reviewer can follow in under ten minutes.
- `needs_validation` carries **no severity**. It states the single most important unresolved fact. If the unresolved fact is "can an attacker control X", the answer is almost always found by reading more code; keep reading before giving up.
- `rejected` is recorded, not deleted. Rejected records stop later runs from re-reporting the same lead.
- Defense-in-depth gaps: record as `confirmed` with `kind: "hardening"` and severity `P3` only if the missing layer is worth adding; otherwise `rejected` with the reason "defended by <layer>".
- When two verifiers disagree, a third decides from source alone and records why.

### Severity calibration

Re-read the rubric in `SKILL.md`. Lower severity when exploitation needs an unusual precondition (admin already compromised, local access, rare configuration). Raise only with a traced path to a higher-impact sink. Chains count: an open redirect that completes an OAuth token theft is rated for the chain, with both locations cited.

## Phase 4: Structured output

Write `findings.json` with one record per candidate that survived Phase 3 (all three verdicts).

```json
{
  "schema_version": 1,
  "project": "example-shop",
  "run": 1,
  "generated": "2026-10-29T00:00:00Z",
  "scope": { "description": "Full audit of main branch", "commit": "abc1234", "excluded": ["vendor/"] },
  "findings": [
    {
      "id": "SEC-001",
      "title": "Orders endpoint lacks tenant predicate (cross-tenant read)",
      "verdict": "confirmed",
      "kind": "vulnerability",
      "severity": "P1",
      "reachability": "authenticated",
      "domains": [19],
      "attack_class": "CORE-07",
      "cwe": ["CWE-639"],
      "owasp": "A01:2025",
      "location": { "file": "src/orders/get.ts", "start_line": 20, "end_line": 41 },
      "source_trace": [
        { "file": "src/orders/get.ts", "line": 21, "role": "source", "note": "id from path" },
        { "file": "src/orders/get.ts", "line": 33, "role": "sink", "note": "query by id only" }
      ],
      "exploit_scenario": "A user in tenant A requests /orders/<id of tenant B order> and receives it, because the query filters on id alone.",
      "evidence": ["src/orders/get.ts:L33 SELECT * FROM orders WHERE id = $1"],
      "impact": "Cross-tenant disclosure of order data.",
      "fix": { "status": "proposed", "summary": "Add tenant predicate and RLS", "diff": "--- a/src/orders/get.ts\n+++ b/src/orders/get.ts\n..." },
      "regression_test": { "status": "proposed", "description": "Two-tenant test expects 404 for foreign order id" },
      "residual_risk": "Other order endpoints must be reviewed for the same pattern.",
      "verification": { "verifier_outcome": "upheld", "record_verified": false }
    }
  ]
}
```

Field rules are enforced by `scripts/validate-findings.cjs` against `report-schema.json`:

- IDs are unique and match `SEC-` plus at least three digits.
- `confirmed`: requires `severity`, `reachability`, `cwe`, `owasp`, `location`, `source_trace` containing at least one `source` and one `sink`, `exploit_scenario`, `evidence`, `impact`, and `verification`. Hardening records (`kind: "hardening"`) must be `P3`.
- `needs_validation`: requires `unresolved_fact` and must not carry `severity`.
- `rejected`: requires `rejection_reason`.
- `domains` are integers 1 to 30. `attack_class` matches the id patterns in the attack-class files.
- `release_recommendation`, if present, must agree with the confirmed counts.

Run the validator, fix every error, and re-run:

```
node scripts/validate-findings.cjs findings.json
```

## Phase 5: Independent record verification

A fresh agent (or a fresh pass in Solo Mode) verifies the final source claims in `findings.json`. This is a check on the record, not a second hunt.

### Record verifier prompt

```
You are a record verifier. For each finding in findings.json with verdict confirmed:
1. Open every cited file and line. Confirm the code exists at those lines and says what the
   record claims. Wrong line numbers or paraphrased code are errors.
2. Confirm the source_trace is a real path: each hop calls the next.
3. Confirm the severity follows the rubric and the reachability is correct.
4. Confirm the fix diff (if present) applies to the cited lines and does not break the
   documented behavior.
5. Report each error as {id, field, problem, corrected_value}. Do not add new findings.
```

Rules:

- Material replacements (a changed verdict, severity, or root cause) get a second independent record verifier.
- Apply corrections, set `verification.record_verified` to `true`, and re-run the validator with `--final`:

```
node scripts/validate-findings.cjs findings.json --final
```

- Re-run the validator after every Phase 5 replacement.

## Phase 7: Reporting and release gate

1. Run the 12 gates in `GATES.md`. Record result and evidence for each (`pass`, `fail`, `not_run` with reason).
2. Render the reports from the verified records. Do not hand-write findings into the reports.

```
node scripts/render-report.cjs findings.json --ledger coverage-ledger.json --gates gates.json --out .
```

Outputs:

| File | Contents |
| :--- | :--- |
| `REPORT.md` | Executive summary, release recommendation, counts, coverage summary, confirmed findings grouped by reachability then severity, hardening notes, gate results |
| `FINDINGS-DETAIL.md` | Full record for each confirmed finding: trace, exploit scenario, evidence, impact, fix diff, regression test, residual risk |
| `NEEDS-VALIDATION.md` | Each `needs_validation` lead with the exact unresolved fact and how to settle it |

3. Optionally export SARIF for code scanning dashboards:

```
node scripts/to-sarif.cjs findings.json > findings.sarif
```

4. Final message to the person: release recommendation, counts by severity, top three risks in plain language, what was not covered and why, and the exact next step.

### Release recommendation

- **Block:** any confirmed `P0`.
- **Fix before release:** no `P0`, at least one confirmed `P1`, or any failed gate that maps to a `P1`.
- **Accept with tracked ticket:** only `P2` and `P3` remain and each has a ticket id or owner recorded.

State what the recommendation depends on. If coverage was incomplete (blocked units, missing sandbox, missing scanners), say so in the same paragraph.

### Report principles

- Lead with what matters. Do not bury a P0 under 40 hardening notes.
- Plain language first, then evidence. A manager should understand the exploit scenario.
- No live secret values anywhere.
- Every claim traces to a record. Every record traces to source.
- Keep hardening notes in their own section and short.
