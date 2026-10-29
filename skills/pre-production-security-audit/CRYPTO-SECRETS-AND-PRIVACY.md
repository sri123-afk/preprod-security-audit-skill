# Cryptography, Secrets, and Privacy Classes (CRY-01 to CRY-12)

Format per class: **Hunt**, **Confirms**, **Not a finding**. Never write secret values into artifacts; record location and type.

## CRY-01: Randomness and token generation

- **Hunt:** `Math.random`, `rand()`, `System.Random`, time-seeded or sequential values for tokens, reset codes, ids, session ids, API keys, CSRF tokens, or nonces; short numeric codes without attempt limits.
- **Confirms:** Tokens are predictable or brute-forceable within realistic limits.
- **Not a finding:** CSPRNG with adequate length.

## CRY-02: Password and credential storage

- **Hunt:** Plain text, reversible encryption, MD5 or SHA-family hashes, unsalted hashes, low-cost bcrypt, custom schemes, secrets compared with `==`, default credentials, credentials in config or code.
- **Confirms:** A database read yields recoverable credentials, or defaults grant access.
- **Not a finding:** Argon2id, scrypt, or tuned bcrypt with per-user salts.

## CRY-03: Encryption misuse

- **Hunt:** ECB mode, static or reused IV or nonce (especially GCM and CTR), unauthenticated encryption, encrypt-then-forget MAC, homemade constructions, keys derived from passwords with weak KDFs, short keys, encryption keys stored beside data, deterministic encryption of low-entropy fields.
- **Confirms:** Ciphertext can be forged, decrypted, or correlated.
- **Not a finding:** AEAD with unique nonces from vetted libraries.

## CRY-04: JWT, signing, and key handling

- **Hunt:** Shared symmetric keys across services or environments, keys in source or images, no rotation or key id, verification keys fetched from untrusted URLs, signatures over ambiguous serializations, key confusion, signing oracles reachable by users.
- **Confirms:** An attacker can forge, replay across environments, or obtain signing material.
- **Not a finding:** Per-environment keys in a managed vault with rotation.

## CRY-05: Secrets in code, history, images, and logs

- **Hunt:** Secrets in the working tree, full git history, build logs, container layers, CI variables echoed, Terraform state, source maps, crash reports, analytics, support tools, shared documents referenced by the repo, `.env` files committed or deployed.
- **Confirms:** A live secret is exposed (verify format and ownership without using it). Any hit in git history is P0 until rotated.
- **Not a finding:** Example placeholders and test fixtures with no real authority.

## CRY-06: Secret management and rotation

- **Hunt:** No vault, secrets distributed by email or chat, same secret everywhere, no owner or rotation schedule, no revocation runbook, secrets that cannot be rotated without downtime, developer machines holding production credentials.
- **Confirms:** A leak could not be contained quickly. Report as P2 unless combined with exposure.
- **Not a finding:** Documented rotation with automation and least-privilege access.

## CRY-07: TLS and certificate handling

- **Hunt:** TLS below 1.2, weak ciphers, verification disabled, self-signed trust in production, missing HSTS, internal service traffic unencrypted across trust zones, certificate expiry without monitoring.
- **Confirms:** Interception or downgrade is feasible on a sensitive path.
- **Not a finding:** Development-only configuration that cannot ship.

## CRY-08: Time, clocks, and expiry

- **Hunt:** Token and link expiry computed with client time or local time, timezone and DST errors in billing and trials, clock skew tolerances that are too large, leap-second and year-2038 handling in security-relevant counters, comparisons of dates as strings.
- **Confirms:** An expired credential, trial, or window remains valid or a valid one fails, with security or financial effect.
- **Not a finding:** UTC storage with bounded skew and monotonic ordering.

## CRY-09: Personal data inventory and consent

- **Hunt:** Personal data collected before consent, analytics and marketing scripts firing pre-consent, data collected with no stated purpose, sensitive categories without extra safeguards, children's data, location, biometrics, and health data, data sent to third parties without contract review.
- **Confirms:** A concrete collection or transfer lacks consent or legal basis for the target regions.
- **Not a finding:** Consent-gated collection with documented purposes.

## CRY-10: Retention, deletion, and data subject rights

- **Hunt:** No retention schedule, deletion that misses caches, indexes, logs, analytics, backups, and processors, no export or deletion workflow, no identity verification for requests, immortal soft deletes of personal data.
- **Confirms:** Required deletion or access cannot be fulfilled with the current design.
- **Not a finding:** Documented retention classes and a tested deletion pipeline.

## CRY-11: Regional privacy and sector obligations

- **Hunt:** Residency and transfer obligations for the markets served (for example GDPR, CCPA and CPRA, Bahrain PDPL, Saudi PDPL, Sri Lanka PDPA), PCI DSS scope (card data touching your servers or logs), health and financial sector rules, breach notification readiness. Verify current applicability and thresholds for each deployment region; do not assume.
- **Confirms:** A system design plainly conflicts with an obligation that applies to its users or data. Frame as compliance risk with a recommendation to involve counsel.
- **Not a finding:** Legal conclusions beyond the evidence. Report as P3 or `needs_validation` when applicability is unknown.

## CRY-12: Logging and telemetry hygiene

- **Hunt:** Passwords, tokens, card numbers, session ids, full personal data, and request bodies in logs, error trackers, analytics events, APM traces, and support tools; log forging via unescaped user data; no redaction layer; debug logging enabled in production.
- **Confirms:** Sensitive data is stored in systems with broader access or longer retention than intended.
- **Not a finding:** Redaction at the logger and scrubbing in third-party tools.
