# Contributing

Contributions that make audits more accurate are welcome.

## Adding or changing an attack class

1. Pick the right file in `skills/pre-production-security-audit/` and the next free id in its range (for example `WEB-19`).
2. Use the three-part format: **Hunt**, **Confirms**, **Not a finding**. The "Not a finding" line is required; it prevents false positives.
3. Update the routing table in `HUNTING.md` if the class should be assigned automatically.
4. If the class maps to a domain, check `DOMAIN-MATRIX.md`.
5. Keep claims verifiable. For version-specific facts (CVEs, framework defaults) say to check the pinned version and the current advisory, and link the primary source in the pull request.

## Changing scripts or the schema

- Scripts must stay zero-dependency CommonJS and run on Node.js 18 or later.
- Keep `report-schema.json` and `scripts/validate-findings.cjs` in agreement.
- Add or update tests in `skills/pre-production-security-audit/tests/` and run `npm test`.

## Style

- Plain, precise language. No emojis and no em dashes.
- No live credentials, real customer data, or working exploit chains against named products.
- Do not copy text from other projects. Describe ideas in your own words and credit sources.

## Reporting a problem with the skill

Open an issue with the prompt you used, the tool and model, and what went wrong (false positive, missed class, bad severity). Redact secrets and private code.
