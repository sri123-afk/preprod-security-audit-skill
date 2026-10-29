# Agent instructions

This repository contains one skill: `skills/pre-production-security-audit/`.

When the user asks for a security audit, vulnerability review, pen-test of code, hardening review, or a "check before launch", read `skills/pre-production-security-audit/SKILL.md` and follow it. Read the other files in that folder only when the active phase tells you to.

If you cannot read files or spawn agents, use `skills/pre-production-security-audit/SINGLE-PASS.md` or Solo Mode as described in SKILL.md.

Rules that always apply:

- Confirm only findings with a traced source, a missing or bypassable check, and a reachable sink.
- Never run target code outside an OS-enforced sandbox. Never test production or third-party systems.
- Never write live secret values into any file or message.
- Validate artifacts with the scripts in `skills/pre-production-security-audit/scripts/` when Node.js is available.

To work on this repository itself: run `npm test` (Node.js 18 or later, no dependencies), keep text free of em dashes and emojis, and add a test for any change to a validator or renderer.
