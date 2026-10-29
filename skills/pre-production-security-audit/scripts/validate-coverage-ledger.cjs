#!/usr/bin/env node
"use strict";
// Zero-dependency validator for coverage-ledger.json.
// Usage: node validate-coverage-ledger.cjs coverage-ledger.json [--complete]
//   --complete additionally requires every unit to be checked, not_applicable, or blocked.
// Exit codes: 0 valid, 1 validation errors, 2 usage or read error.

const fs = require("node:fs");

const STATUSES = ["pending", "in_progress", "checked", "blocked", "not_applicable"];
const PRIORITIES = ["high", "medium", "low"];
const RESULTS = ["no_issue", "candidate", "blocked", "not_applicable"];
const UNIT_RE = /^U-\d+$/;
const CLASS_RE = /^((CORE|WEB|CLI|SC|CLD|DATA|RES|AI|MOB|CRY)-\d{2}|STK-[A-Z]+-\d{2})$/;

const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v) => typeof v === "string" && v.trim().length > 0;

function validateLedger(doc, opts = {}) {
  const errors = [];
  const err = (p, m) => errors.push(`${p}: ${m}`);

  if (!isObj(doc)) return { errors: ["$: document must be a JSON object"] };
  if (doc.schema_version !== 1) err("$.schema_version", "must be 1");
  if (!isStr(doc.project)) err("$.project", "must be a non-empty string");
  if (!Number.isInteger(doc.run) || doc.run < 1) err("$.run", "must be an integer >= 1");
  if (doc.stack_profiles !== undefined && !(Array.isArray(doc.stack_profiles) && doc.stack_profiles.every((s) => typeof s === "string"))) {
    err("$.stack_profiles", "must be an array of strings");
  }
  if (!Array.isArray(doc.units) || doc.units.length === 0) {
    err("$.units", "must be a non-empty array");
    return { errors };
  }

  const ids = new Set();
  doc.units.forEach((u, i) => {
    const p = `$.units[${i}]`;
    if (!isObj(u)) return err(p, "must be an object");
    if (!isStr(u.id) || !UNIT_RE.test(u.id)) err(`${p}.id`, "must match U-<digits>");
    else if (ids.has(u.id)) err(`${p}.id`, `duplicate unit id ${u.id}`);
    else ids.add(u.id);
    const label = isStr(u.id) ? u.id : p;

    if (!isStr(u.name)) err(`${label}.name`, "must be a non-empty string");
    if (!Array.isArray(u.files) || u.files.length === 0 || !u.files.every(isStr)) err(`${label}.files`, "must be a non-empty array of paths");
    if (!Array.isArray(u.domains) || u.domains.length === 0 || !u.domains.every((d) => Number.isInteger(d) && d >= 1 && d <= 30)) {
      err(`${label}.domains`, "must be a non-empty array of integers 1 to 30");
    }
    if (!Array.isArray(u.attack_classes) || u.attack_classes.length === 0 || !u.attack_classes.every((c) => typeof c === "string" && CLASS_RE.test(c))) {
      err(`${label}.attack_classes`, "must be a non-empty array of valid class ids");
    }
    if (!PRIORITIES.includes(u.priority)) err(`${label}.priority`, `must be one of ${PRIORITIES.join(", ")}`);
    if (!STATUSES.includes(u.status)) err(`${label}.status`, `must be one of ${STATUSES.join(", ")}`);
    if ((u.status === "blocked" || u.status === "not_applicable") && !isStr(u.reason)) {
      err(`${label}.reason`, `${u.status} units require a reason`);
    }
    if (!Array.isArray(u.checks)) {
      err(`${label}.checks`, "must be an array");
      return;
    }

    u.checks.forEach((c, j) => {
      const cp = `${label}.checks[${j}]`;
      if (!isObj(c)) return err(cp, "must be an object");
      if (!isStr(c.class) || !CLASS_RE.test(c.class)) err(`${cp}.class`, "must be a valid class id");
      if (!RESULTS.includes(c.result)) err(`${cp}.result`, `must be one of ${RESULTS.join(", ")}`);
      if (c.result === "no_issue" || c.result === "candidate") {
        if (!Array.isArray(c.evidence) || c.evidence.length === 0 || !c.evidence.every(isStr)) err(`${cp}.evidence`, `${c.result} requires evidence (file:line strings)`);
      }
      if ((c.result === "blocked" || c.result === "not_applicable") && !isStr(c.note)) err(`${cp}.note`, `${c.result} requires a note with the reason`);
      if (c.result === "candidate" && !isStr(c.candidate_id)) err(`${cp}.candidate_id`, "candidate checks require candidate_id");
    });

    if (u.status === "checked") {
      if (u.checks.length === 0) err(`${label}.checks`, "a checked unit cannot have an empty checks list");
      const covered = new Set(u.checks.map((c) => c && c.class));
      for (const cls of Array.isArray(u.attack_classes) ? u.attack_classes : []) {
        if (!covered.has(cls)) err(`${label}.checks`, `checked unit has no check for assigned class ${cls}`);
      }
    }
    if (opts.complete && (u.status === "pending" || u.status === "in_progress")) {
      err(`${label}.status`, `${u.status} units are not allowed in --complete mode`);
    }
  });
  return { errors };
}

module.exports = { validateLedger };

if (require.main === module) {
  const args = process.argv.slice(2);
  const complete = args.includes("--complete");
  const file = args.find((a) => !a.startsWith("--"));
  if (!file) {
    console.error("Usage: node validate-coverage-ledger.cjs <coverage-ledger.json> [--complete]");
    process.exit(2);
  }
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (e) {
    console.error(`Cannot read or parse ${file}: ${e.message}`);
    process.exit(2);
  }
  const { errors } = validateLedger(doc, { complete });
  if (errors.length) {
    errors.forEach((e) => console.error(`error: ${e}`));
    console.error(`\n${errors.length} error(s) in ${file}`);
    process.exit(1);
  }
  const counts = {};
  doc.units.forEach((u) => { counts[u.status] = (counts[u.status] || 0) + 1; });
  console.log(`OK: ${file} (${doc.units.length} units: ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(", ")})`);
}
