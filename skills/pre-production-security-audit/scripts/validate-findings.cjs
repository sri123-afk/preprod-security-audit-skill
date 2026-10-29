#!/usr/bin/env node
"use strict";
// Zero-dependency validator for findings.json (see ../report-schema.json).
// Usage: node validate-findings.cjs findings.json [--final]
// Exit codes: 0 valid, 1 validation errors, 2 usage or read error.

const fs = require("node:fs");

const VERDICTS = ["confirmed", "needs_validation", "rejected"];
const SEVERITIES = ["P0", "P1", "P2", "P3"];
const REACHABILITY = ["unauthenticated_remote", "authenticated", "local_or_internal"];
const ROLES = ["source", "propagation", "check", "sink"];
const KINDS = ["vulnerability", "hardening"];
const RECOMMENDATIONS = ["Block", "Fix before release", "Accept with tracked ticket"];
const ID_RE = /^SEC-\d{3,}$/;
const CLASS_RE = /^((CORE|WEB|CLI|SC|CLD|DATA|RES|AI|MOB|CRY)-\d{2}|STK-[A-Z]+-\d{2})$/;
const CWE_RE = /^CWE-\d+$/;
const OWASP_RE = /^A(0[1-9]|10):2025$/;
const ASI_RE = /^ASI(0[1-9]|10)$/;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v) => typeof v === "string" && v.trim().length > 0;
const isPosInt = (v) => Number.isInteger(v) && v >= 1;

function computeRecommendation(findings) {
  const confirmed = (findings || []).filter((f) => f && f.verdict === "confirmed" && f.kind !== "hardening");
  if (confirmed.some((f) => f.severity === "P0")) return "Block";
  if (confirmed.some((f) => f.severity === "P1")) return "Fix before release";
  return "Accept with tracked ticket";
}

function validateFindings(doc, opts = {}) {
  const errors = [];
  const warnings = [];
  const err = (path, msg) => errors.push(`${path}: ${msg}`);
  const warn = (path, msg) => warnings.push(`${path}: ${msg}`);

  if (!isObj(doc)) {
    return { errors: ["$: document must be a JSON object"], warnings };
  }
  const allowedTop = ["schema_version", "project", "run", "generated", "scope", "release_recommendation", "findings"];
  for (const k of Object.keys(doc)) if (!allowedTop.includes(k)) err("$", `unknown top-level field "${k}"`);
  if (doc.schema_version !== 1) err("$.schema_version", "must be 1");
  if (!isStr(doc.project)) err("$.project", "must be a non-empty string");
  if (!isPosInt(doc.run)) err("$.run", "must be an integer >= 1");
  if (!isStr(doc.generated) || Number.isNaN(Date.parse(doc.generated))) err("$.generated", "must be an ISO date-time string");
  if (doc.scope !== undefined && !isObj(doc.scope)) err("$.scope", "must be an object");
  if (doc.release_recommendation !== undefined && !RECOMMENDATIONS.includes(doc.release_recommendation)) {
    err("$.release_recommendation", `must be one of ${RECOMMENDATIONS.join(", ")}`);
  }
  if (!Array.isArray(doc.findings)) {
    err("$.findings", "must be an array");
    return { errors, warnings };
  }

  const seen = new Set();
  doc.findings.forEach((f, i) => {
    const p = `$.findings[${i}]`;
    if (!isObj(f)) return err(p, "must be an object");

    if (!isStr(f.id) || !ID_RE.test(f.id)) err(`${p}.id`, "must match SEC-<3+ digits>");
    else if (seen.has(f.id)) err(`${p}.id`, `duplicate id ${f.id}`);
    else seen.add(f.id);
    const label = isStr(f.id) ? f.id : p;

    if (!isStr(f.title) || f.title.trim().length < 5) err(`${label}.title`, "must be at least 5 characters");
    if (!VERDICTS.includes(f.verdict)) err(`${label}.verdict`, `must be one of ${VERDICTS.join(", ")}`);
    if (f.kind !== undefined && !KINDS.includes(f.kind)) err(`${label}.kind`, `must be one of ${KINDS.join(", ")}`);
    if (f.severity !== undefined && !SEVERITIES.includes(f.severity)) err(`${label}.severity`, `must be one of ${SEVERITIES.join(", ")}`);
    if (f.reachability !== undefined && !REACHABILITY.includes(f.reachability)) err(`${label}.reachability`, `must be one of ${REACHABILITY.join(", ")}`);

    if (!Array.isArray(f.domains) || f.domains.length === 0 || !f.domains.every((d) => Number.isInteger(d) && d >= 1 && d <= 30)) {
      err(`${label}.domains`, "must be a non-empty array of integers 1 to 30");
    }
    if (!isStr(f.attack_class) || !CLASS_RE.test(f.attack_class)) err(`${label}.attack_class`, "must be a valid class id such as CORE-07 or STK-NEXT-01");
    if (f.cwe !== undefined && !(Array.isArray(f.cwe) && f.cwe.every((c) => typeof c === "string" && CWE_RE.test(c)))) err(`${label}.cwe`, "must be an array of CWE-<number>");
    if (f.owasp !== undefined && !(typeof f.owasp === "string" && OWASP_RE.test(f.owasp))) err(`${label}.owasp`, "must look like A01:2025 (A01 to A10)");
    if (f.asi !== undefined && !(typeof f.asi === "string" && ASI_RE.test(f.asi))) err(`${label}.asi`, "must look like ASI01 to ASI10");

    if (f.location !== undefined) {
      const l = f.location;
      if (!isObj(l) || !isStr(l.file) || !isPosInt(l.start_line) || !isPosInt(l.end_line)) err(`${label}.location`, "needs file, start_line, end_line");
      else if (l.end_line < l.start_line) err(`${label}.location`, "end_line is before start_line");
    }

    let trace = [];
    if (f.source_trace !== undefined) {
      if (!Array.isArray(f.source_trace)) err(`${label}.source_trace`, "must be an array");
      else {
        trace = f.source_trace;
        trace.forEach((s, j) => {
          if (!isObj(s) || !isStr(s.file) || !isPosInt(s.line) || !ROLES.includes(s.role)) {
            err(`${label}.source_trace[${j}]`, `needs file, line, and role (${ROLES.join(", ")})`);
          }
        });
      }
    }
    if (f.evidence !== undefined && !(Array.isArray(f.evidence) && f.evidence.length > 0 && f.evidence.every((e) => typeof e === "string"))) {
      err(`${label}.evidence`, "must be a non-empty array of strings");
    }
    if (f.verification !== undefined) {
      const v = f.verification;
      if (!isObj(v) || !["upheld", "downgraded", "replaced", "not_run"].includes(v.verifier_outcome) || typeof v.record_verified !== "boolean") {
        err(`${label}.verification`, "needs verifier_outcome (upheld|downgraded|replaced|not_run) and boolean record_verified");
      }
    }

    if (f.verdict === "confirmed") {
      for (const req of ["severity", "reachability", "cwe", "owasp", "location", "source_trace", "exploit_scenario", "evidence", "impact", "verification"]) {
        if (f[req] === undefined) err(`${label}`, `confirmed finding requires "${req}"`);
      }
      if (isStr(f.exploit_scenario) && f.exploit_scenario.trim().length < 20) err(`${label}.exploit_scenario`, "must be at least 20 characters");
      if (!isStr(f.impact) && f.impact !== undefined) err(`${label}.impact`, "must be a non-empty string");
      if (Array.isArray(f.cwe) && f.cwe.length === 0) err(`${label}.cwe`, "must contain at least one CWE");
      if (Array.isArray(f.source_trace)) {
        if (!trace.some((s) => s && s.role === "source")) err(`${label}.source_trace`, "needs at least one step with role source");
        if (!trace.some((s) => s && s.role === "sink")) err(`${label}.source_trace`, "needs at least one step with role sink");
      }
      if (f.kind === "hardening" && f.severity !== undefined && f.severity !== "P3") err(`${label}.severity`, "hardening findings must be P3");
      if (opts.final) {
        if (!(isObj(f.verification) && f.verification.record_verified === true)) err(`${label}.verification`, "record_verified must be true in --final mode");
        if (isObj(f.verification) && f.verification.verifier_outcome === "not_run") err(`${label}.verification`, "verifier_outcome must not be not_run in --final mode");
        if ((f.severity === "P0" || f.severity === "P1") && f.kind !== "hardening" && !isObj(f.regression_test)) {
          warn(`${label}.regression_test`, "P0 and P1 findings should include a regression test");
        }
      }
    }
    if (f.verdict === "needs_validation") {
      if (!isStr(f.unresolved_fact)) err(`${label}.unresolved_fact`, "needs_validation requires unresolved_fact");
      if (f.severity !== undefined) err(`${label}.severity`, "needs_validation must not carry a severity");
    }
    if (f.verdict === "rejected") {
      if (!isStr(f.rejection_reason)) err(`${label}.rejection_reason`, "rejected requires rejection_reason");
      if (f.severity !== undefined) warn(`${label}.severity`, "rejected findings should not carry a severity");
    }
  });

  if (doc.release_recommendation !== undefined && errors.length === 0) {
    const expected = computeRecommendation(doc.findings);
    const order = { "Accept with tracked ticket": 0, "Fix before release": 1, "Block": 2 };
    if (order[doc.release_recommendation] < order[expected]) {
      err("$.release_recommendation", `"${doc.release_recommendation}" is too lenient for the confirmed findings (expected at least "${expected}")`);
    }
  }
  return { errors, warnings };
}

module.exports = { validateFindings, computeRecommendation };

if (require.main === module) {
  const args = process.argv.slice(2);
  const final = args.includes("--final");
  const file = args.find((a) => !a.startsWith("--"));
  if (!file) {
    console.error("Usage: node validate-findings.cjs <findings.json> [--final]");
    process.exit(2);
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`Cannot read or parse ${file}: ${e.message}`);
    process.exit(2);
  }
  const { errors, warnings } = validateFindings(doc, { final });
  warnings.forEach((w) => console.warn(`warning: ${w}`));
  if (errors.length) {
    errors.forEach((e) => console.error(`error: ${e}`));
    console.error(`\n${errors.length} error(s) in ${file}`);
    process.exit(1);
  }
  const n = doc.findings.length;
  console.log(`OK: ${file} (${n} record${n === 1 ? "" : "s"}${final ? ", final mode" : ""})`);
}
