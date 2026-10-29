# AI, LLM, and Agent Classes (AI-01 to AI-12)

Use for any unit that calls a model, builds prompts, retrieves documents, runs tools, uses MCP servers, stores memory, or renders model output. Model output is untrusted input. Retrieved content is untrusted input. Tool results are untrusted input.

Mapping to the OWASP Top 10 for Agentic Applications 2026 (ASI01 to ASI10): goal hijack, tool misuse, identity and privilege abuse, agentic supply chain, unexpected code execution, memory and context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, rogue agents. Tag findings with the closest ASI id in the `asi` field. Also cover the OWASP LLM Top 10 themes (prompt injection, sensitive information disclosure, supply chain, improper output handling, excessive agency, system prompt leakage, vector and embedding weaknesses, misinformation, unbounded consumption).

Format per class: **Hunt**, **Confirms**, **Not a finding**.

## AI-01: Direct prompt injection and instruction hierarchy

- **Hunt:** User text concatenated into system or developer prompts, role markers accepted from users, prompts that grant authority based on user claims ("I am the admin"), safety or policy logic implemented only in prompt text.
- **Confirms:** A user can make the model ignore a control that is enforced only by the prompt and the model then performs a protected action.
- **Not a finding:** Model produces undesired text with no protected action, data, or cost impact (P3 at most).

## AI-02: Indirect prompt injection (ASI01)

- **Hunt:** Emails, documents, web pages, issues, tickets, chat messages, calendar items, PDFs, images, tool outputs, and retrieved chunks placed in context without being marked as data; agents that act on instructions found in content; browsing agents with access to credentials or authenticated sessions.
- **Confirms:** Attacker-authored content in a source the agent reads can cause a privileged tool call or data disclosure.
- **Not a finding:** Content is treated as data and any action requires confirmation or is outside the agent's authority.

## AI-03: Excessive agency and tool permissions (ASI02, ASI03)

- **Hunt:** Tools with write or delete rights where read suffices, shared service credentials, tools not scoped per user or task, tool arguments passed to SQL, shell, HTTP, or file APIs unvalidated, no human approval for irreversible actions (payments, deletions, external messages, permission changes), agents acting with the developer's identity instead of the end user's.
- **Confirms:** A manipulated or mistaken agent can perform an action the end user could not or should not authorize.
- **Not a finding:** Per-user scoped credentials, allowlisted tools, validated arguments, approval gates.

## AI-04: Exfiltration channels

- **Hunt:** Markdown images and links rendered from model output (data in URL), tool calls to attacker-chosen URLs, email or message tools with free recipients, DNS and webhook tools, clipboard and file-write tools, link previews that fetch model-supplied URLs.
- **Confirms:** Sensitive context can be sent to an attacker-controlled endpoint through output rendering or a tool.
- **Not a finding:** Remote rendering stripped or proxied, egress allowlist, recipients restricted.

## AI-05: Improper output handling

- **Hunt:** Model output inserted as HTML, SQL, shell, file paths, URLs, code to execute, JSON passed to privileged APIs, or used as an authorization decision, without validation and encoding.
- **Confirms:** Model output reaches an injection sink or makes a security decision.
- **Not a finding:** Output validated against strict schemas and encoded for its context.

## AI-06: Code execution and sandboxing (ASI05)

- **Hunt:** Code interpreters and tool runners with network, secrets, host mounts, or long-lived filesystems; no CPU, memory, and time limits; shared sandboxes across users; package installation at runtime; generated code executed in the application process.
- **Confirms:** Model-generated or user-supplied code can reach secrets, the network, other users' data, or the host.
- **Not a finding:** Ephemeral no-network sandbox with limits and no secrets.

## AI-07: MCP servers, plugins, and agentic supply chain (ASI04)

- **Hunt:** Unvetted or unpinned MCP servers and plugins, tool descriptions that can inject instructions, overbroad OAuth scopes, servers that can change behavior after approval (rug pull), tools loaded from URLs, community skills and prompts with hidden instructions, configs that auto-start servers on project open.
- **Confirms:** An untrusted tool, description, or update can steer the agent or access data it should not.
- **Not a finding:** Pinned and reviewed servers with least-privilege scopes and call logging.

## AI-08: Memory, context, and RAG poisoning (ASI06)

- **Hunt:** Persistent memory writable from untrusted content, cross-tenant or cross-user retrieval, documents ingested without provenance or access control, embeddings and vector stores without tenant filters, retrieval results trusted as authoritative, no deletion path for poisoned entries.
- **Confirms:** Attacker content persists and influences later sessions or other users, or retrieval crosses a tenant boundary.
- **Not a finding:** Tenant-scoped indexes, provenance tags, reviewed memory writes.

## AI-09: Multi-agent and inter-agent trust (ASI07, ASI08)

- **Hunt:** Agents trusting messages from other agents as instructions, no authentication between agents, unbounded delegation loops, cascading actions with no circuit breaker, shared credentials across agents, agent-generated approvals treated as human approvals.
- **Confirms:** One compromised or mistaken agent can trigger privileged actions or cascading failures across others.
- **Not a finding:** Authenticated, least-privilege inter-agent channels with limits and loop detection.

## AI-10: Human-agent trust and approval design (ASI09, ASI10)

- **Hunt:** Approval prompts that hide arguments, batch approvals, fatigue-prone flows, agent explanations that can be forged by injected content, agents that can modify their own permissions or configuration, no kill switch, no audit trail of tool calls.
- **Confirms:** A reviewer cannot see what they approve, or the agent can expand its own authority.
- **Not a finding:** Full-argument approvals, immutable audit log, kill switch.

## AI-11: Sensitive data, prompt leakage, and provider terms

- **Hunt:** Secrets, keys, or personal data placed in prompts, system prompts treated as secrets, personal data sent to third-party model providers without legal basis or contract review, logs of full prompts and completions, training or retention terms not reviewed, cross-user cache of completions.
- **Confirms:** Sensitive data is exposed to a party or log it should not reach, or another user's completion can be served from cache.
- **Not a finding:** Data minimization, redaction, reviewed provider terms.

## AI-12: Unbounded consumption and model abuse

- **Hunt:** No per-user token or request budgets, unbounded context and recursion, agent loops with no step limits, anonymous access to expensive models, no timeouts on model calls, prompt-controlled tool fan-out, model denial through huge inputs.
- **Confirms:** An attacker can drive cost or latency far beyond intended limits.
- **Not a finding:** Budgets, step limits, timeouts, kill switch.
