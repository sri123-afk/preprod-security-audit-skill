# Supply Chain, CI, and Release Classes (SC-01 to SC-14)

Recent registry worms and pipeline compromises show that attackers target maintainers, CI tokens, and install-time hooks, and sometimes publish malicious versions from legitimate pipelines with valid provenance. Provenance proves where code was built, not that it is safe.

Format per class: **Hunt**, **Confirms**, **Not a finding**.

## SC-01: Install-time and lifecycle script execution

- **Hunt:** `preinstall`, `install`, `postinstall`, `prepare` scripts in direct and transitive dependencies, `setup.py` execution, Cargo `build.rs`, NuGet install scripts and MSBuild targets, Gradle plugins, Git dependencies, `curl | sh` in docs or Dockerfiles.
- **Confirms:** A dependency or project script runs arbitrary code at install or build time with access to secrets in the environment, and the project does not restrict it.
- **Not a finding:** Scripts disabled by default (`ignore-scripts=true`) with a reviewed allowlist.

## SC-02: Malicious, compromised, and typosquatted packages

- **Hunt:** Obfuscated code, base64 or hex blobs executed at runtime, network calls to unknown hosts at install, credential-file reads (`.npmrc`, `.aws`, `.ssh`, browser stores, cloud tokens), wipers or conditional geo or locale triggers, maintainer changes, sudden version jumps, packages with near-identical names to popular ones, abandoned packages recently transferred.
- **Confirms:** A package in the lockfile or import graph exhibits malicious behavior or is a known-compromised version. Treat as P0 and recommend credential rotation.
- **Not a finding:** Minified legitimate code with a known upstream and matching hash.

## SC-03: Dependency confusion and registry configuration

- **Hunt:** Internal package names unregistered on public registries, missing scope or source mapping, multiple registries without precedence rules, `--extra-index-url`, auth tokens in committed `.npmrc` or `NuGet.config`, registries over HTTP.
- **Confirms:** An attacker can publish a higher-version public package that resolves instead of the internal one.
- **Not a finding:** Scoped namespaces owned by the organization and source mapping enforced.

## SC-04: Lockfiles, pinning, and release-age policy

- **Hunt:** Missing lockfile, ranges (`^`, `~`, `latest`) in CI installs, `npm install` instead of `npm ci`, `pip install` without hashes, `dotnet restore` without locked mode, `cargo` without `--locked`, no minimum release age, Docker `latest` tags, unpinned GitHub Action references.
- **Confirms:** A fresh malicious release would be pulled automatically into builds.
- **Not a finding:** Lockfile committed and enforced in CI with a documented upgrade process.

## SC-05: GitHub Actions privileged triggers

- **Hunt:** `pull_request_target` or `workflow_run` that checks out, builds, or executes code from the pull request head, untrusted `${{ github.event.* }}` interpolated into `run:`, issue and comment triggers that run with secrets, artifacts from fork runs consumed by privileged workflows.
- **Confirms:** A fork or external contributor can run code with repository secrets or write tokens.
- **Not a finding:** Unprivileged build with no secrets, then a separate privileged job that handles only inert data.

## SC-06: CI cache and artifact poisoning

- **Hunt:** Cache keys shared between untrusted and release workflows, restore of caches in publish jobs, build outputs downloaded without verification, shared runners with persistent workspaces, artifact names predictable across runs.
- **Confirms:** An untrusted job can write a cache or artifact later consumed by a privileged job.
- **Not a finding:** Cache scoped per ref and disabled in release jobs.

## SC-07: Tokens, OIDC, and secret exposure in pipelines

- **Hunt:** Default `GITHUB_TOKEN` with write permissions, `permissions:` missing, `id-token: write` granted to jobs that run third-party code, long-lived registry or cloud keys in repository secrets, secrets echoed or written to logs and artifacts, workload identity federation with wildcard subjects, secrets available to preview deployments of forks.
- **Confirms:** A job running untrusted code can obtain a token that publishes, deploys, or reads secrets.
- **Not a finding:** Least-privilege per-job permissions, environment-scoped secrets with required reviewers, subjects scoped to repo and environment.

## SC-08: Action and third-party tool pinning

- **Hunt:** Actions referenced by tag or branch, composite actions pulling remote scripts, self-hosted runners on public repos, Docker images from unverified publishers, tools downloaded in CI without checksum verification.
- **Confirms:** A moved tag or compromised publisher changes code executed in CI.
- **Not a finding:** Full commit SHA pinning with automated review of updates.

## SC-09: Release, publishing, and signing

- **Hunt:** Publish without human gate, 2FA not required on registry accounts, publish tokens that can publish any package, unsigned artifacts, signing keys on CI disks, no provenance or checksum, release from a branch anyone can push to, version bumps by bots with write access.
- **Confirms:** A single compromised account or workflow can ship code to users.
- **Not a finding:** Protected release environment, two-person approval, trusted publishing, signed artifacts.

## SC-10: Auto-update and plugin or extension channels

- **Hunt:** Updaters over HTTP or without signature verification, update host not pinned, plugin and extension loading from user-writable paths, remote code or config fetched at runtime and executed, dynamic `import` of URLs.
- **Confirms:** A network or file-system attacker can deliver code to installed clients.
- **Not a finding:** Signed updates with pinned keys and hosts.

## SC-11: Build reproducibility and base images

- **Hunt:** Floating base images, root build stages, secrets passed as build args, multi-stage builds leaking files, vulnerable base layers, `apt-get` without pinning in security-sensitive images, no SBOM.
- **Confirms:** Secrets or vulnerable components ship in the image, or the image cannot be traced to a source commit.
- **Not a finding:** Pinned digests, distroless or minimal final stage, build secrets mounted not baked.

## SC-12: Vulnerable and outdated components

- **Hunt:** Advisories for each direct dependency at the pinned version (check at audit time, not from memory), end-of-life runtimes, framework versions affected by known auth bypass or remote code execution advisories, transitive packages with known exploited vulnerabilities.
- **Confirms:** A vulnerable version is present and the vulnerable code path is reachable. Otherwise report as hardening with upgrade guidance.
- **Not a finding:** Advisory for a code path the project never reaches (document why).

## SC-13: Developer machine and agent tooling exposure

- **Hunt:** Committed editor, MCP, or AI agent configs that auto-run commands, project-level hooks executing on open, shared dev containers with host mounts, `.vscode/tasks.json` autorun, long-lived tokens expected on laptops.
- **Confirms:** Opening or building the repository executes attacker-chosen code on a developer machine.
- **Not a finding:** Configs requiring explicit user approval for each command.

## SC-14: License and provenance compliance

- **Hunt:** Copyleft or non-commercial licenses in distributed binaries, missing attribution, copied snippets with incompatible licenses, vendored code without upstream reference.
- **Confirms:** A concrete license obligation is unmet for how the software is distributed.
- **Not a finding:** Licenses compatible with the distribution model. Report legal items as P3 and recommend counsel review.
