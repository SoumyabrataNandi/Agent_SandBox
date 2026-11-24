# Cycle 4 — Requirements Verification Questions (ship and pilot)

## Starting point
Cycles 1–3 delivered the whole original brief (phases 1–5): the sandbox, CLI/HTTP/MCP, the network broker, OTLP, pooling, snapshots, sessions and published benchmarks. All NFR-P1 targets were met (bench run 45334900239). CI is green on 4 OSes at 7d53a22.

What blocks real use today:
- **No sandboxd release exists.** The only GitHub releases are the `interp-*` interpreter builds, so users must build from source. `release.yml` (tag `v*` → draft release) has never run, and its `macos-15-intel` target has never been built in CI.
- **Advisories surface late.** RUSTSEC-2026-0587 and RUSTSEC-2026-0592 were found only because someone pushed; the supply-chain job doesn't run on a schedule and dependency updates are manual.
- **No end-to-end agent pilot.** MCP is covered by Rust integration tests, but nobody has driven `sandboxd mcp` the way an agent does: a real stdio client making a sequence of realistic calls.
- **No install guide or changelog**, and no vulnerability-reporting policy for a public repo.

User instruction (2026-11-24): *"start cycle 4 all are approved from my end and select all default values"*. Every answer below is the recommended option.

---

### Question 1 — Cycle 4 scope
A) **Ship and pilot:** supply-chain automation + security policy, an MCP agent pilot (harness in CI, fix what it finds), getting-started docs + changelog, and the **v0.1.0 release**. **(Recommended: turns the finished brief into something people can install and trust)**
B) A new feature first (pure-Python packages from a wheelhouse, or a container fallback for native extensions), release later
C) Release only
D) Other

[Answer]: A

### Question 2 — Keeping up with advisories
A) **Dependabot** (weekly: Cargo and GitHub Actions) **plus a scheduled `security` workflow** (daily + manual): cargo-deny advisories and cargo-audit against `main`. On failure it opens (or updates) one GitHub issue labelled `security`, and it writes `security/latest.json` to `ci-results` so I can read it with `git fetch`. **(Recommended)**
B) Dependabot only
C) Scheduled workflow only
D) Other

[Answer]: A

### Question 3 — Vulnerability disclosure
A) **`SECURITY.md`**: report privately through GitHub private vulnerability reporting (security advisories), what's in scope (sandbox escapes, policy bypasses, audit evasion, DoS through limits), supported versions (latest release), and response targets. **(Recommended)**
B) A security email address
C) Other

[Answer]: A

### Question 4 — The MCP pilot
A) **A stdlib Python MCP client** (`scripts/pilot/mcp_pilot.py`) that starts `sandboxd mcp` over stdio, does the real handshake, and runs agent-shaped scenarios: list tools/policies, CSV analysis with `/in` files and `/out` artifacts, an error and traceback, a limit hit, an unsupported native import, a multi-cell session, JavaScript, and progress streaming. Each check is asserted. It runs as a CI job on Linux and Windows, and every friction point it finds is fixed in this cycle or logged. **(Recommended)**
B) Manual pilot in Claude Code only (not repeatable)
C) Other

[Answer]: A

### Question 5 — Getting started
A) **`docs/GETTING_STARTED.md`**: download a release, verify `SHA256SUMS` and the build attestation, first run, connect Claude Code / Claude Desktop, run as a service, write a policy. **`CHANGELOG.md`** (Keep a Changelog format) with a `0.1.0` entry. The README gets an Install section. Release archives ship both, and the release notes come from the changelog entry. **(Recommended)**
B) README only
C) Other

[Answer]: A

### Question 6 — Release
A) **Tag `v0.1.0` once CI is green.** `release.yml` builds 5 targets, runs the escape suite on each, and **creates a draft release** with archives, `SHA256SUMS` and attestations. I check the draft through the public API; **you publish it** with one click (the draft step is a deliberate human review). **(Recommended)**
B) Publish automatically (no draft)
C) Don't release this cycle

[Answer]: A

### Question 7 — Container image
A) **Not this cycle.** Binaries first; a container image (GHCR) is a cycle 5 candidate. **(Recommended: keeps the first release small)**
B) Also publish a container image on GHCR

[Answer]: A
