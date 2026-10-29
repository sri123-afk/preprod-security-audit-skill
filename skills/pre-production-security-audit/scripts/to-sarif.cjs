#!/usr/bin/env node
"use strict";
// Exports confirmed findings as SARIF 2.1.0 for code scanning dashboards.
// Usage: node to-sarif.cjs findings.json > findings.sarif

const fs = require("node:fs");

const LEVEL = { P0: "error", P1: "error", P2: "warning", P3: "note" };

function toSarif(doc) {
  const confirmed = doc.findings.filter((f) => f.verdict === "confirmed");
  const rules = [];
  const ruleIndex = new Map();
  confirmed.forEach((f) => {
    if (!ruleIndex.has(f.attack_class)) {
      ruleIndex.set(f.attack_class, rules.length);
      rules.push({
        id: f.attack_class,
        name: f.attack_class,
        shortDescription: { text: `Attack class ${f.attack_class}` },
        properties: { tags: ["security"] },
      });
    }
  });
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "pre-production-security-audit", informationUri: "https://github.com/sri123-afk/preprod-security-audit-skill", rules } },
        results: confirmed.map((f) => ({
          ruleId: f.attack_class,
          ruleIndex: ruleIndex.get(f.attack_class),
          level: LEVEL[f.severity] || "warning",
          message: { text: `${f.id} ${f.title}. ${f.exploit_scenario}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location.file },
                region: { startLine: f.location.start_line, endLine: f.location.end_line },
              },
            },
          ],
          properties: {
            id: f.id,
            severity: f.severity,
            reachability: f.reachability,
            cwe: f.cwe,
            owasp: f.owasp,
            kind: f.kind || "vulnerability",
          },
        })),
      },
    ],
  };
}

module.exports = { toSarif };

if (require.main === module) {
  const file = process.argv[2];
  if (!file) {
    console.error("Usage: node to-sarif.cjs <findings.json>");
    process.exit(2);
  }
  try {
    process.stdout.write(JSON.stringify(toSarif(JSON.parse(fs.readFileSync(file, "utf8"))), null, 2) + "\n");
  } catch (e) {
    console.error(`to-sarif failed: ${e.message}`);
    process.exit(2);
  }
}
