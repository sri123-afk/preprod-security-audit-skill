"use strict";
// Run with: node --test tests/
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execFileSync, spawnSync } = require("node:child_process");

const { validateFindings, computeRecommendation } = require("../scripts/validate-findings.cjs");
const { validateLedger } = require("../scripts/validate-coverage-ledger.cjs");
const { renderReport, renderDetail, renderNeeds } = require("../scripts/render-report.cjs");
const { toSarif } = require("../scripts/to-sarif.cjs");

const load = (n) => JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", n), "utf8"));
const clone = (o) => JSON.parse(JSON.stringify(o));

test("valid findings fixture passes, including --final", () => {
  const doc = load("valid-findings.json");
  assert.deepEqual(validateFindings(doc).errors, []);
  assert.deepEqual(validateFindings(doc, { final: true }).errors, []);
});

test("confirmed finding without a sink step is rejected", () => {
  const doc = clone(load("valid-findings.json"));
  doc.findings[0].source_trace = [doc.findings[0].source_trace[0]];
  const { errors } = validateFindings(doc);
  assert.ok(errors.some((e) => e.includes("role sink")));
});

test("needs_validation must not carry severity and must state the unresolved fact", () => {
  const doc = clone(load("valid-findings.json"));
  doc.findings[1].severity = "P1";
  delete doc.findings[1].unresolved_fact;
  const { errors } = validateFindings(doc);
  assert.ok(errors.some((e) => e.includes("must not carry a severity")));
  assert.ok(errors.some((e) => e.includes("unresolved_fact")));
});

test("rejected requires a reason", () => {
  const doc = clone(load("valid-findings.json"));
  delete doc.findings[2].rejection_reason;
  assert.ok(validateFindings(doc).errors.some((e) => e.includes("rejection_reason")));
});

test("duplicate ids and bad id format are rejected", () => {
  const doc = clone(load("valid-findings.json"));
  doc.findings[1].id = "SEC-001";
  doc.findings[2].id = "BUG-3";
  const { errors } = validateFindings(doc);
  assert.ok(errors.some((e) => e.includes("duplicate id")));
  assert.ok(errors.some((e) => e.includes("SEC-<3+ digits>")));
});

test("hardening findings must be P3", () => {
  const doc = clone(load("valid-findings.json"));
  doc.findings[3].severity = "P2";
  assert.ok(validateFindings(doc).errors.some((e) => e.includes("hardening findings must be P3")));
});

test("--final requires record_verified", () => {
  const doc = clone(load("valid-findings.json"));
  doc.findings[0].verification.record_verified = false;
  assert.deepEqual(validateFindings(doc).errors, []);
  assert.ok(validateFindings(doc, { final: true }).errors.some((e) => e.includes("record_verified")));
});

test("release recommendation cannot be more lenient than the findings", () => {
  const doc = clone(load("valid-findings.json"));
  doc.release_recommendation = "Accept with tracked ticket";
  assert.ok(validateFindings(doc).errors.some((e) => e.includes("too lenient")));
  doc.release_recommendation = "Fix before release";
  assert.deepEqual(validateFindings(doc).errors, []);
  assert.equal(computeRecommendation(doc.findings), "Fix before release");
  doc.findings[0].severity = "P0";
  assert.equal(computeRecommendation(doc.findings), "Block");
});

test("invalid class, domain, CWE, and OWASP values are rejected", () => {
  const doc = clone(load("valid-findings.json"));
  const f = doc.findings[0];
  f.attack_class = "XYZ-1";
  f.domains = [0, 31];
  f.cwe = ["639"];
  f.owasp = "A11:2025";
  const { errors } = validateFindings(doc);
  for (const needle of ["attack_class", "domains", "cwe", "owasp"]) {
    assert.ok(errors.some((e) => e.includes(needle)), `expected an error mentioning ${needle}`);
  }
});

test("valid ledger passes; blocked units need a reason", () => {
  const ledger = load("valid-ledger.json");
  assert.deepEqual(validateLedger(ledger).errors, []);
  const bad = clone(ledger);
  delete bad.units[1].reason;
  assert.ok(validateLedger(bad).errors.some((e) => e.includes("require a reason")));
});

test("checked unit must have a check for every assigned class", () => {
  const ledger = clone(load("valid-ledger.json"));
  ledger.units[0].checks = [ledger.units[0].checks[0]];
  assert.ok(validateLedger(ledger).errors.some((e) => e.includes("WEB-09")));
});

test("candidate checks need evidence and candidate_id; --complete rejects pending units", () => {
  const ledger = clone(load("valid-ledger.json"));
  delete ledger.units[0].checks[1].candidate_id;
  delete ledger.units[0].checks[1].evidence;
  const { errors } = validateLedger(ledger);
  assert.ok(errors.some((e) => e.includes("candidate_id")));
  assert.ok(errors.some((e) => e.includes("evidence")));

  const pending = clone(load("valid-ledger.json"));
  pending.units[0].status = "pending";
  assert.deepEqual(validateLedger(pending).errors, []);
  assert.ok(validateLedger(pending, { complete: true }).errors.some((e) => e.includes("--complete")));
});

test("renderer derives reports from records only", () => {
  const doc = load("valid-findings.json");
  const ledger = load("valid-ledger.json");
  const gates = { gates: [{ id: 7, status: "pass", evidence: "gitleaks full history, 0 hits" }] };
  const report = renderReport(doc, ledger, gates, computeRecommendation(doc.findings));
  assert.match(report, /Release recommendation: Fix before release/);
  assert.match(report, /### Authenticated/);
  assert.match(report, /Hardening notes/);
  assert.match(report, /Blocked units/);
  assert.match(report, /SEC-002/);
  assert.match(renderDetail(doc), /## SEC-001/);
  assert.match(renderNeeds(doc), /Unresolved fact/);
});

test("SARIF contains confirmed findings only", () => {
  const sarif = toSarif(load("valid-findings.json"));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results.length, 2);
  assert.equal(sarif.runs[0].results[0].level, "error");
});

test("CLI exit codes: 0 valid, 1 invalid, 2 unreadable", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-"));
  const script = path.join(__dirname, "..", "scripts", "validate-findings.cjs");
  const good = path.join(__dirname, "fixtures", "valid-findings.json");
  execFileSync(process.execPath, [script, good]);
  const badFile = path.join(dir, "bad.json");
  fs.writeFileSync(badFile, JSON.stringify({ schema_version: 1 }));
  assert.equal(spawnSync(process.execPath, [script, badFile]).status, 1);
  assert.equal(spawnSync(process.execPath, [script, path.join(dir, "missing.json")]).status, 2);
});

test("render-report CLI writes the three reports", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-out-"));
  const script = path.join(__dirname, "..", "scripts", "render-report.cjs");
  execFileSync(process.execPath, [script, path.join(__dirname, "fixtures", "valid-findings.json"), "--ledger", path.join(__dirname, "fixtures", "valid-ledger.json"), "--out", dir]);
  for (const f of ["REPORT.md", "FINDINGS-DETAIL.md", "NEEDS-VALIDATION.md"]) assert.ok(fs.existsSync(path.join(dir, f)), `${f} missing`);
});
