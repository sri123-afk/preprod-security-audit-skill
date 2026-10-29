#!/usr/bin/env node
"use strict";
// Renders REPORT.md, FINDINGS-DETAIL.md, and NEEDS-VALIDATION.md from findings.json.
// Usage: node render-report.cjs findings.json [--ledger coverage-ledger.json] [--gates gates.json] [--out DIR]
// Reports are derived only from the records. Run validate-findings.cjs first.

const fs = require("node:fs");
const path = require("node:path");
const { computeRecommendation } = require("./validate-findings.cjs");

const REACH_ORDER = ["unauthenticated_remote", "authenticated", "local_or_internal"];
const REACH_LABEL = {
  unauthenticated_remote: "Unauthenticated remote",
  authenticated: "Authenticated",
  local_or_internal: "Local or internal",
};
const SEV_ORDER = { P0: 0, P1: 1, P2: 2, P3: 3 };

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function esc(s) {
  return String(s == null ? "" : s).replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function loc(f) {
  return f.location ? `${f.location.file}:L${f.location.start_line}-L${f.location.end_line}` : "n/a";
}

function renderReport(findings, ledger, gates, recommendation) {
  const confirmed = findings.findings.filter((f) => f.verdict === "confirmed");
  const vulns = confirmed.filter((f) => f.kind !== "hardening");
  const hardening = confirmed.filter((f) => f.kind === "hardening");
  const needs = findings.findings.filter((f) => f.verdict === "needs_validation");
  const rejected = findings.findings.filter((f) => f.verdict === "rejected");
  const count = (sev) => vulns.filter((f) => f.severity === sev).length;

  const out = [];
  out.push(`# Security Audit Report: ${findings.project}`);
  out.push("");
  out.push(`Run ${findings.run}, generated ${findings.generated}.`);
  if (findings.scope) {
    if (findings.scope.description) out.push(`Scope: ${findings.scope.description}.`);
    if (findings.scope.commit) out.push(`Commit: \`${findings.scope.commit}\`.`);
    if (findings.scope.excluded && findings.scope.excluded.length) out.push(`Excluded: ${findings.scope.excluded.join(", ")}.`);
  }
  out.push("");
  out.push(`## Release recommendation: ${recommendation}`);
  out.push("");
  out.push("| P0 | P1 | P2 | P3 | Hardening | Needs validation | Rejected |");
  out.push("| :-- | :-- | :-- | :-- | :-- | :-- | :-- |");
  out.push(`| ${count("P0")} | ${count("P1")} | ${count("P2")} | ${count("P3")} | ${hardening.length} | ${needs.length} | ${rejected.length} |`);
  out.push("");
  out.push("Severity: P0 release blocker, P1 fix before launch, P2 current sprint, P3 hardening. Only confirmed records carry severity.");
  out.push("");

  if (ledger && Array.isArray(ledger.units)) {
    const c = {};
    ledger.units.forEach((u) => { c[u.status] = (c[u.status] || 0) + 1; });
    out.push("## Coverage");
    out.push("");
    out.push(`Units: ${ledger.units.length}. ` + Object.entries(c).map(([k, v]) => `${k}: ${v}`).join(", ") + ".");
    const blocked = ledger.units.filter((u) => u.status === "blocked");
    if (blocked.length) {
      out.push("");
      out.push("Blocked units (coverage gaps):");
      blocked.forEach((u) => out.push(`- ${u.id} ${u.name}: ${u.reason}`));
    }
    out.push("");
  }

  out.push("## Confirmed findings");
  out.push("");
  if (vulns.length === 0) out.push("No confirmed vulnerabilities.");
  for (const reach of REACH_ORDER) {
    const group = vulns
      .filter((f) => f.reachability === reach)
      .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
    if (!group.length) continue;
    out.push(`### ${REACH_LABEL[reach]}`);
    out.push("");
    out.push("| ID | Severity | Title | Location | Class | CWE | OWASP 2025 |");
    out.push("| :-- | :-- | :-- | :-- | :-- | :-- | :-- |");
    group.forEach((f) => {
      out.push(`| ${f.id} | ${f.severity} | ${esc(f.title)} | \`${esc(loc(f))}\` | ${f.attack_class} | ${(f.cwe || []).join(", ")} | ${f.owasp} |`);
    });
    out.push("");
    group.forEach((f) => {
      out.push(`**${f.id}** ${esc(f.exploit_scenario)}`);
      out.push("");
    });
  }

  if (hardening.length) {
    out.push("## Hardening notes");
    out.push("");
    hardening.forEach((f) => out.push(`- **${f.id}** ${esc(f.title)} (\`${esc(loc(f))}\`)`));
    out.push("");
  }

  if (needs.length) {
    out.push("## Needs validation");
    out.push("");
    out.push("See NEEDS-VALIDATION.md. These leads carry no severity until the unresolved fact is settled.");
    out.push("");
    needs.forEach((f) => out.push(`- **${f.id}** ${esc(f.title)}: ${esc(f.unresolved_fact)}`));
    out.push("");
  }

  if (gates && Array.isArray(gates.gates)) {
    out.push("## Verification gates");
    out.push("");
    out.push("| Gate | Status | Evidence or reason | Findings |");
    out.push("| :-- | :-- | :-- | :-- |");
    gates.gates.slice().sort((a, b) => a.id - b.id).forEach((g) => {
      out.push(`| ${g.id} | ${g.status} | ${esc(g.evidence || g.reason || "")} | ${(g.finding_ids || []).join(", ")} |`);
    });
    out.push("");
  }
  return out.join("\n") + "\n";
}

function renderDetail(findings) {
  const confirmed = findings.findings
    .filter((f) => f.verdict === "confirmed")
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.id.localeCompare(b.id));
  const out = [`# Findings Detail: ${findings.project}`, ""];
  if (!confirmed.length) out.push("No confirmed findings.", "");
  confirmed.forEach((f) => {
    out.push(`## ${f.id} ${f.title}`, "");
    out.push(`- Severity: ${f.severity}${f.kind === "hardening" ? " (hardening)" : ""}`);
    out.push(`- Reachability: ${REACH_LABEL[f.reachability] || f.reachability}`);
    out.push(`- Class: ${f.attack_class}; domains: ${f.domains.join(", ")}`);
    out.push(`- Classification: ${(f.cwe || []).join(", ")}; OWASP ${f.owasp}${f.asi ? `; ${f.asi}` : ""}`);
    out.push(`- Location: \`${loc(f)}\``);
    if (f.verification) out.push(`- Verification: ${f.verification.verifier_outcome}; record verified: ${f.verification.record_verified}`);
    out.push("", "### Exploit scenario", "", f.exploit_scenario, "", "### Impact", "", f.impact || "", "", "### Trace", "");
    (f.source_trace || []).forEach((s) => out.push(`- ${s.role}: \`${s.file}:L${s.line}\`${s.note ? ` ${s.note}` : ""}`));
    out.push("", "### Evidence", "");
    (f.evidence || []).forEach((e) => out.push(`- ${e}`));
    if (f.fix) {
      out.push("", `### Fix (${f.fix.status || "proposed"})`, "");
      if (f.fix.summary) out.push(f.fix.summary, "");
      if (f.fix.diff) out.push("```diff", f.fix.diff, "```");
    }
    if (f.regression_test) {
      out.push("", `### Regression test (${f.regression_test.status || "proposed"})`, "");
      if (f.regression_test.description) out.push(f.regression_test.description);
      if (f.regression_test.path) out.push("", `Path: \`${f.regression_test.path}\``);
    }
    if (f.residual_risk) out.push("", "### Residual risk", "", f.residual_risk);
    out.push("");
  });
  return out.join("\n") + "\n";
}

function renderNeeds(findings) {
  const needs = findings.findings.filter((f) => f.verdict === "needs_validation");
  const out = [`# Needs Validation: ${findings.project}`, ""];
  if (!needs.length) out.push("No open leads.", "");
  needs.forEach((f) => {
    out.push(`## ${f.id} ${f.title}`, "");
    out.push(`- Class: ${f.attack_class}; domains: ${f.domains.join(", ")}`);
    if (f.location) out.push(`- Location: \`${loc(f)}\``);
    out.push("", "### Unresolved fact", "", f.unresolved_fact, "");
    if (f.source_trace && f.source_trace.length) {
      out.push("### Trace so far", "");
      f.source_trace.forEach((s) => out.push(`- ${s.role}: \`${s.file}:L${s.line}\`${s.note ? ` ${s.note}` : ""}`));
      out.push("");
    }
  });
  return out.join("\n") + "\n";
}

module.exports = { renderReport, renderDetail, renderNeeds };

if (require.main === module) {
  const args = process.argv.slice(2);
  const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const file = args.find((a, i) => !a.startsWith("--") && !["--ledger", "--gates", "--out"].includes(args[i - 1]));
  if (!file) {
    console.error("Usage: node render-report.cjs <findings.json> [--ledger file] [--gates file] [--out dir]");
    process.exit(2);
  }
  try {
    const findings = loadJson(file);
    const ledger = opt("--ledger") ? loadJson(opt("--ledger")) : null;
    const gates = opt("--gates") ? loadJson(opt("--gates")) : null;
    const outDir = opt("--out") || ".";
    const recommendation = findings.release_recommendation || computeRecommendation(findings.findings);
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "REPORT.md"), renderReport(findings, ledger, gates, recommendation));
    fs.writeFileSync(path.join(outDir, "FINDINGS-DETAIL.md"), renderDetail(findings));
    fs.writeFileSync(path.join(outDir, "NEEDS-VALIDATION.md"), renderNeeds(findings));
    console.log(`Wrote REPORT.md, FINDINGS-DETAIL.md, NEEDS-VALIDATION.md to ${outDir} (recommendation: ${recommendation})`);
  } catch (e) {
    console.error(`render-report failed: ${e.message}`);
    process.exit(2);
  }
}
