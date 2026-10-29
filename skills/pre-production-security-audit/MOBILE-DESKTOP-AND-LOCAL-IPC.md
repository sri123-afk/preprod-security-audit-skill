# Mobile, Desktop, and Local IPC Classes (MOB-01 to MOB-12)

Use for Flutter, native mobile, Electron and other webview shells, desktop apps, helper daemons, and local inter-process channels. Remember the client is controlled by the attacker: anything shipped in the binary can be extracted and anything sent from it can be forged. Format per class: **Hunt**, **Confirms**, **Not a finding**.

## MOB-01: Secrets and keys in the shipped app

- **Hunt:** API keys, signing secrets, service credentials, and private endpoints in Dart code, assets, `--dart-define` values, native resources, `strings.xml`, `Info.plist`, config JSON, bundled `.env`, Firebase configs with permissive rules. Debug and staging endpoints left in release builds.
- **Confirms:** A secret with server-side power is extractable from the binary.
- **Not a finding:** Public client identifiers restricted by package id, bundle id, and API scope.

## MOB-02: Insecure local storage

- **Hunt:** Tokens and personal data in `SharedPreferences`, `NSUserDefaults`, plain SQLite, Hive boxes, files, or logs; no use of Keychain or Keystore; backups enabled for sensitive data (`allowBackup`); screenshots and task-switcher snapshots of sensitive screens; clipboard use for secrets; Keychain items surviving uninstall without cleanup.
- **Confirms:** Credentials or personal data can be read from a lost, backed-up, or rooted device by a plausible attacker.
- **Not a finding:** Hardware-backed secure storage, short-lived tokens, backup exclusion.

## MOB-03: Transport security and pinning

- **Hunt:** Cleartext allowed (Android `usesCleartextTraffic`, network security config, iOS ATS exceptions), certificate validation callbacks that return true, custom trust managers, no pinning for high-risk apps with no rotation plan, pinning libraries bypassed by debug flags in release.
- **Confirms:** A network attacker can intercept or alter credentialed traffic.
- **Not a finding:** Standard TLS validation for low-risk data; pinning is a hardening measure with an operational cost.

## MOB-04: Authentication in the app

- **Hunt:** OAuth in embedded webviews, custom URL schemes for redirects (hijackable), no PKCE, biometrics used as the only authentication (local gate not tied to a key), token refresh without rotation or revocation, client-side-only session checks, root or jailbreak detection treated as a control.
- **Confirms:** Another app or attacker can intercept auth codes or bypass authentication on the device.
- **Not a finding:** System-browser flows with PKCE and claimed https links; biometrics bound to Keystore keys.

## MOB-05: Deep links, intents, and exported components

- **Hunt:** Exported Android activities, services, receivers, and providers without permissions, intent extras trusted, deep link parameters used for navigation, file access, or auth without validation, universal link and app link verification missing, implicit intents carrying sensitive data, pending intents mutable.
- **Confirms:** A hostile app or web page can trigger privileged actions or read data through links or intents.
- **Not a finding:** Components not exported, parameters validated, server enforces authorization independent of the link.

## MOB-06: WebViews and embedded browsers

- **Hunt:** JavaScript enabled on untrusted content, JavaScript bridges and channels exposed to remote pages, `file://` access, mixed content, no navigation allowlist, `loadUrl` with user input, third-party content with the same bridge as first-party, cookies shared with the system browser.
- **Confirms:** Remote or injected content can call native capabilities or read app data.
- **Not a finding:** Local-only content or strict origin allowlist with a minimal bridge.

## MOB-07: Electron and desktop shells

- **Hunt:** `nodeIntegration` on, `contextIsolation` off, `sandbox` off, `webSecurity` disabled, remote content with preload bridges, wide-open IPC handlers, `shell.openExternal` with user data, protocol handlers, `enableRemoteModule`, devtools in release, auto-open of downloaded files.
- **Confirms:** XSS or hostile content can become native code execution or file access.
- **Not a finding:** Isolation and sandbox on, typed minimal IPC, navigation allowlist, strict CSP.

## MOB-08: Local IPC, daemons, and helpers

- **Hunt:** Local HTTP servers listening on `0.0.0.0` or without authentication, predictable ports, named pipes and sockets with broad permissions, DNS rebinding against local servers, helper services running as root or SYSTEM that trust unprivileged callers, shared memory without access control, temp files in world-writable paths.
- **Confirms:** A local unprivileged process, web page, or other user can drive the helper or read its data.
- **Not a finding:** Loopback only with per-session secret, restrictive permissions, authenticated callers.

## MOB-09: Updaters and installers

- **Hunt:** Updates over HTTP or without signature verification, user-writable install directories executed by privileged processes, DLL and library search order hijacking, unsigned installers, installers that fetch and run scripts, downgrade attacks, update host not pinned.
- **Confirms:** A network or local attacker can deliver or elevate code through the update or install path.
- **Not a finding:** Signed packages, pinned update origin, protected install paths.

## MOB-10: Platform configuration

- **Hunt:** `android:debuggable`, test builds shipped, `FLAG_SECURE` missing on sensitive screens, permissions beyond need, exported file providers, `minSdk` and deployment targets with known weaknesses, release signing keys on CI disks or in repos, Play App Signing not used, iOS entitlements broader than required, background modes unneeded.
- **Confirms:** Configuration enables a concrete attack found elsewhere or exposes data.
- **Not a finding:** Minor hardening with no path (P3).

## MOB-11: Client trust and anti-abuse

- **Hunt:** Prices, entitlements, roles, and limits computed on the device and accepted by the server, license checks only on the client, no server-side verification of in-app purchases or receipts, relying on root detection or attestation as authorization, no rate limits for mobile endpoints, leaked admin features behind client flags.
- **Confirms:** A modified client obtains paid features, altered prices, or elevated access.
- **Not a finding:** Server-side verification and enforcement. Attestation (Play Integrity, App Attest) is a signal, not authorization.

## MOB-12: Mobile and desktop dependencies and logging

- **Hunt:** Native plugins with broad permissions or native code, git dependencies unpinned, abandoned plugins, crash reporters and analytics receiving personal data or tokens, verbose logs in release (`print`, `debugPrint`, `NSLog`, `Log.d`), debug menus.
- **Confirms:** A dependency or telemetry path leaks sensitive data or adds an attack surface not justified by function.
- **Not a finding:** Reviewed plugins, redacted telemetry, release logging stripped.
