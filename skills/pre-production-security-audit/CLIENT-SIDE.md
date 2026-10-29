# Client-Side Classes (CLI-01 to CLI-10)

Use for browser code, rendered HTML, markdown or rich-text pipelines, embedded webviews, and any frontend bundle. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## CLI-01: DOM XSS sinks

- **Hunt:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `bypassSecurityTrust*`, `eval` and `setTimeout` with strings, `location` assignments from `location.hash` or query, jQuery `.html()`, `srcdoc`, `javascript:` and `data:` URLs in `href` or `src`, template literals building HTML.
- **Confirms:** Attacker-controlled data reaches an HTML or script sink without contextual encoding or a vetted sanitizer.
- **Not a finding:** Framework default text bindings, sanitizer with a strict allowlist applied at the sink, Trusted Types enforced.

## CLI-02: Stored and reflected XSS in rendering pipelines

- **Hunt:** Markdown and MDX renderers with raw HTML enabled, rich-text editors, SVG uploads, email templates, PDF and print views, server-rendered error pages echoing input, admin dashboards rendering user content, JSON embedded in script tags without escaping `</script>` and `<!--`.
- **Confirms:** Stored or reflected content executes in another user's or admin's session.
- **Not a finding:** Output encoded for its context and served with a CSP that blocks inline script (still note hardening if CSP is the only defense).

## CLI-03: Cross-window messaging and origin trust

- **Hunt:** `postMessage` listeners without `event.origin` and `event.source` checks, `targetOrigin: "*"` with sensitive data, `window.opener` reachable (missing `noopener`), iframe `sandbox` absent or too loose, `BroadcastChannel` and `storage` events trusted, OAuth popup flows leaking codes.
- **Confirms:** A hostile origin can send commands or read data through the channel.
- **Not a finding:** Exact origin allowlist checked before acting, minimal payload.

## CLI-04: Clickjacking and UI redress

- **Hunt:** Sensitive actions (payment, delete, permission grant, OAuth consent) on pages framable by other origins, missing `frame-ancestors` and `X-Frame-Options`, drag-and-drop and tap-jacking on mobile webviews.
- **Confirms:** A framed page can trick a user into a state-changing action.
- **Not a finding:** `frame-ancestors 'none'` or same-origin where needed.

## CLI-05: Client-side prototype pollution and DOM clobbering

- **Hunt:** Recursive merge or query-string parsers (`qs`, `deparam`, `lodash.merge/set`, `jQuery.extend(true, ...)`), `__proto__` and `constructor` keys from URL or JSON, gadget sinks that read polluted properties into `innerHTML`, script URLs, or config, `id` and `name` attributes overriding globals.
- **Confirms:** Pollution reaches a gadget that changes security behavior. Name the source and gadget.
- **Not a finding:** Pollution possible with no reachable gadget (hardening, P3).

## CLI-06: Secrets and sensitive config in client bundles

- **Hunt:** `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_` variables holding secrets, API keys with write scope, database URLs, admin tokens, shipped `.env`, source maps in production (`productionBrowserSourceMaps`, `devtool`), feature flags carrying private rules, comments and test credentials, server-only code imported into client modules.
- **Confirms:** A secret or privileged endpoint credential is retrievable from the shipped bundle or maps.
- **Not a finding:** Public identifiers designed to be public (publishable keys, analytics ids) restricted by origin or scope.

## CLI-07: Client-side authorization and value trust

- **Hunt:** Role checks, entitlements, prices, discounts, and feature gates decided in the client and accepted by the server, hidden fields and disabled buttons as controls, client-computed totals, route guards without server enforcement.
- **Confirms:** Altering client state or request fields grants access or changes value on the server.
- **Not a finding:** UI hiding backed by server enforcement.

## CLI-08: Third-party scripts, SRI, and CSP

- **Hunt:** Tag managers, chat widgets, analytics, ad scripts, and CDN-loaded libraries with full DOM access on authenticated or payment pages, no Subresource Integrity, floating versions, `unsafe-inline` CSP making XSS trivial, payment pages not isolated in provider iframes or hosted fields.
- **Confirms:** A third-party compromise could read credentials or card data because it is not isolated. Rate P1 only on payment or credential pages.
- **Not a finding:** Scripts isolated to marketing pages with no sensitive data.

## CLI-09: URL and navigation handling

- **Hunt:** `window.open` and `location` with user URLs, link rendering of user-supplied `href` (`javascript:`), deep link parsing in webviews, `target=_blank` without `rel=noopener`, redirect params consumed client-side, URL parsers disagreeing with server validators.
- **Confirms:** Attacker URL executes script, redirects after authentication, or bypasses an allowlist.
- **Not a finding:** URLs parsed with `URL` and protocol and host allowlists.

## CLI-10: Client-side storage of credentials and personal data

- **Hunt:** Access or refresh tokens in `localStorage`, `sessionStorage`, or IndexedDB where XSS can read them, personal data cached in service workers, sensitive data in URLs and history, autofill and clipboard leakage, service workers caching authenticated responses.
- **Confirms:** Token or personal data theft is feasible given another confirmed XSS or shared-device scenario. Otherwise P3 hardening.
- **Not a finding:** HttpOnly cookies with CSRF defenses, short-lived memory-only tokens.
