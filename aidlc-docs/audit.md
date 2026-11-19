# AI-DLC Audit Log

## Workflow Start
**Timestamp**: 2026-11-18
**User Input**: "use ai-dlc" + full problem statement: *"Agents increasingly solve tasks by writing code and running it ... Phase 5, performance: snapshots, pooling, persistent sessions, and published benchmarks against Docker. Hard numbers are what get open-source projects noticed."* (WASM sandbox `sandboxd` for untrusted agent code: Rust + wasmtime, CPython WASI / QuickJS, policy-as-code, instance pool, virtual FS, network broker, audit telemetry, MCP `run_code` tool, 5-phase build path.)
**AI Response**: Began AI-DLC Inception.
**Context**: Workflow initiation

---

## Workspace Detection
**Timestamp**: 2026-11-18
**Findings**: `d:\Agent-SandBox` is empty, not a git repo. Rust toolchain (rustup/cargo) not installed. Python 3.13 and Node 26.4 available. Windows 11 host.
**Decision**: Greenfield → skip Reverse Engineering → proceed to Requirements Analysis.

---

## Requirements Analysis — Questions Issued
**Timestamp**: 2026-11-18
**AI Response**: Created `aidlc-docs/inception/requirements/requirement-verification-questions.md` (22 questions). Awaiting user answers before generating `requirements.md`.
**Context**: INCEPTION — Requirements Analysis, approval gate

---

## Requirements Analysis — Answers Received
**Timestamp**: 2026-11-18
**User Input**: "I have answer all the requirements question"
**Answers**: Q1 B, Q2 A, Q3 A, Q4 B, Q5 A, Q6 B, Q7 B, Q8 B, Q9 B, Q10 C, Q11 A, Q12 A,B,C,D,E, Q13 A, Q14 A, Q15 A,B, Q16 B, Q17 C, Q18 B, Q19 A, Q20 A, Q21 A, Q22 A
**AI Response**: No contradictions found. Deviations from recommendations captured: dual TOML/YAML policy (FR-4.1), raw TCP in broker design (FR-7.3, off by default), all three OSes first-class (NFR-1), install toolchain on Windows (NFR-8). Generated `inception/requirements/requirements.md`. Awaiting approval.
**Context**: INCEPTION — Requirements Analysis, approval gate

---

## Requirements Analysis — Approved
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Requirements approved as drafted (raw TCP retained in broker design, off by default). Proceeding to Workflow Planning.

---

## Workflow Planning — Plan Issued
**Timestamp**: 2026-11-18
**AI Response**: Generated `inception/plans/execution-plan.md`. Execute: Application Design, Units Generation, all Construction stages (Infrastructure Design light). Skip: Reverse Engineering, User Stories. Preliminary units U1–U6. Awaiting approval.
**Context**: INCEPTION — Workflow Planning, approval gate

---

## Workflow Planning — Approved
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Execution plan approved. Proceeding to Application Design.

---

## Application Design — Plan & Questions Issued
**Timestamp**: 2026-11-18
**AI Response**: Researched QuickJS-ng WASI release assets, CPython 3.13 WASI builds, and wasmtime-wasi p1 interception limits. Created `inception/plans/application-design-plan.md` with 6 design questions (FS interception, network bridge, stdlib packaging, execution model, MCP SDK, code layout). Awaiting answers.
**Context**: INCEPTION — Application Design, question gate

---

## Application Design — Answers Received & Artifacts Generated
**Timestamp**: 2026-11-18
**User Input**: "answered"
**Answers**: Q1 B, Q2 A, Q3 A, Q4 A, Q5 A, Q6 A (all recommended)
**AI Response**: Generated `inception/application-design/{components,component-methods,services,component-dependency,decisions}.md`. Key decisions: two-layer linker FS interposer with cap-std preopens as primary enforcement (ADR-001, 2-day spike + fallback), virtual-fd device files for network (ADR-002), async wasmtime (ADR-003), pinned prebuilt interpreters embedded via build.rs (ADR-004). Proposed swapping build order U3/U4. Awaiting approval.
**Context**: INCEPTION — Application Design, approval gate

---

## Application Design — Approved
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Application design approved, including swap of VFS before Runtime. Proceeding to Units Generation.

---

## Units Generation — Units Issued
**Timestamp**: 2026-11-18
**AI Response**: Generated `unit-of-work.md`, `unit-of-work-dependency.md`, `unit-of-work-story-map.md`. Units renumbered in build order: U0 Bootstrap, U1 Policy, U2 Audit, U3 VFS (ADR-001 spike, go/no-go gate), U4 Runtime, U5 Server+CLI, U6 Escape suite+release. Added U0 for toolchain/assets/CI. Awaiting approval.
**Context**: INCEPTION — Units Generation, approval gate

---

## Units Generation — Approved; Construction U0 started
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Began U0 Bootstrap.

---

## U0 — Environment issues & decisions
**Timestamp**: 2026-11-18
**User Input**: (mid-turn) "we are using company laptop, don't have permession to install directly in root."
**Events**:
- MSVC Build Tools via winget failed (exit 1602, elevation unavailable).
- User chose: portable MSVC + WSL. User accepted the VS Build Tools license. The automated portable-MSVC run was blocked by the Claude Code permission classifier, so the user must run it manually.
- WSL Ubuntu 26.04: Rust installed in home dir; `build-essential` needs the user's sudo password.
- C: drive was at 20 MB free. User approved moving toolchains to D: (RUSTUP_HOME=D:\dev\rustup, CARGO_HOME=D:\dev\cargo, user PATH updated). C: Rust copies removed, C: now 6.2 GB free.
**AI decisions (flagged for the U0 gate)**: CPython 3.15.2 instead of 3.13 (latest stable WASI build); assets fetched by script, not build.rs; no zstd.

---

## Environment cleanup
**Timestamp**: 2026-11-18
**User Input**: "you can remove wsl one from my system for now, facing storage issue. all try to remove all unwanted temp files and data, which is useless."
**Actions**: Cleared npm cache, pip cache, user %TEMP% (kept Claude session folder; skipped locked files), VS Code CachedExtensionVSIXs, CrashDumps, accessible C:\Windows\Temp items, D:\dev\_dl. Freed 7.86 GB (C: 6.24 → 14.0 GB free).
WSL: user chose "only remove Rust" (not unregister). `rustup self uninstall` done in Ubuntu. Sparse-VHD reclaim refused by WSL (corruption risk; not forced), so ext4.vhdx stays 4.64 GB; compaction needs admin.
**Decision**: Windows-native build only (portable MSVC) for local dev; CI covers Linux/macOS.

---

## U0 — Build & Test
**Timestamp**: 2026-11-18
**User Input**: "command run and finished"
**AI Response**: Portable MSVC 14.52 detected at D:\dev\msvc. Added scripts/dev-env.ps1. Removed placeholder inter-crate deps (cargo unused-dependency warnings). fmt, clippy -D warnings, tests (2), version smoke, release build (16.5 MB) and the tamper test all pass. Summary in construction/u0-bootstrap/code-summary.md. Awaiting U0 approval plus 3 flagged decisions.

---

## U0 — Approved
**Timestamp**: 2026-11-18
**User Input**: "approved"
**AI Response**: U0 approved, including CPython 3.15.2, fetch-script assets and no zstd. Updated FR-1.2 and ADR-004 accordingly.

---

## U1 + U2 — Design issued
**Timestamp**: 2026-11-18
**AI Response**: Generated `construction/u1-policy/design.md` and `construction/u2-audit/design.md` (functional + scaled NFR/infra), plus `construction/u1-u2-design-questions.md` (7 questions). Research: serde_yaml deprecated; serde-saphyr 2.2.0 maintained, with alias budgets. Renamed fs.open → fs.access. Awaiting answers.

---

## U1 + U2 — Answers, Code Generation, Build & Test
**Timestamp**: 2026-11-18
**User Input**: "answered" (Q1–Q7 all A). Mid-turn earlier: "push code to github with name of Agent_SandBox as a private repo into SoumyabrataNandi github repo"
**AI Response**: Treated the answers as design approval. Implemented sandboxd-policy (serde-saphyr 2.2 hardened, toml 1.x) and sandboxd-audit. fmt, clippy -D warnings and 38 workspace tests pass. GitHub: local repo + commits ready. Creating the repo via API was blocked by the permission classifier (credential read). User asked to create the empty private repo manually.

---

## GitHub push
**Timestamp**: 2026-11-18
**User Input**: "https://github.com/SoumyabrataNandi/Agent_SandBox.git Repo i have created. we should push into this."
**AI Response**: The remote had a GitHub "Initial commit" (stub README), so the push was rejected. Merged with --allow-unrelated-histories, kept the project README, pushed without force. main tracks origin/main.

---

## U1 + U2 approved; U3 ADR-001 spike
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Spike in spikes/adr001 (wasmtime 50.0.2). Trait-wrapper interposer over WasiP1Ctx via the public generic wiggle add_to_linker. All exit criteria met (functional; deny audited; overhead within noise). Findings: catch-all "/" preopen needed to audit out-of-mount opens; audit after delegation; CPython cold start ~0.5–0.8 s vs NFR-3 300 ms; first AOT compile 9 s. Recommendation GO. Awaiting user go/no-go.

---

## U3 — Go decision; design issued
**Timestamp**: 2026-11-18
**User Input**: "go"
**AI Response**: ADR-001 confirmed (trait wrapper). Generated construction/u3-vfs/design.md (layout with catch-all "/", interposer rules V1–V9, inputs/artifacts, stdlib cache) and design-questions.md (6 questions). Awaiting answers.

---

## U3 — Answers, Code Generation, Build & Test
**Timestamp**: 2026-11-18
**User Input**: "accept recommended defaults"
**AI Response**: Implemented sandboxd-vfs (interposer, RunFs, stdlib cache, VFD seam). 6 real-CPython integration tests + 4 unit tests pass; workspace 48 tests, clippy -D warnings clean. Deltas: start-up probes summarized (refines V2); U4 must run python with -I -B -S; hard links into /out refused; quota counts bytes written. Spike removed from tree. Awaiting approval.

---

## U3 approved; U4 design issued
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Measured release startup: CPython print(1) 86–116 ms, imports 433 ms (no .pyc), QuickJS 3 ms, deserialize 7 ms vs compile 5.4 s. NFR-3 met for trivial code. Generated construction/u4-runtime/design.md and design-questions.md (6 questions). Awaiting answers.

---

## U4 — Answers, Code Generation, Build & Test
**Timestamp**: 2026-11-18
**User Input**: "ccept recommended default" (Q1–Q6 → recommended)
**AI Response**: Implemented sandboxd-runtime. 21 tests (AC 1, 2, 3, 6 + cache tamper + concurrency) pass; workspace 69. Policy default fuel raised 2G → 20G after calibration (~4.7G fuel/s). Added /code as a reserved guest path (U1) and a Code mount kind (U3). Awaiting approval.

---

## U4 approved; U5 design issued
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Checked current crates (rmcp 3.11, axum 0.8.9, clap 4.6, prometheus-client 0.26, opentelemetry 0.33). Generated construction/u5-server/design.md and design-questions.md (9 questions). Awaiting answers.

---

## U5 — Answers, Code Generation, Build & Test
**Timestamp**: 2026-11-18
**User Input**: "accept recommended defaults" (Q1–Q9)
**AI Response**: Implemented sandboxd-server (RunService, axum HTTP + SSE, rmcp 3.11 MCP over stdio and Streamable HTTP, bearer auth, Prometheus metrics, config) and the sandboxd CLI. 16 new tests including AC 7 (stdio child process + HTTP with token) and AC 8; workspace 85 tests, clippy clean. OTLP exporter deferred (config reserved). Docs: README, docs/MCP.md, examples. Awaiting approval.

---

## U5 approved; U6 design issued
**Timestamp**: 2026-11-18
**User Input**: "approve"
**AI Response**: Generated construction/u6-escape-release/design.md (15 escape case families E-FS-1..E-AUDIT with canaries, CI gate, perf smoke, release workflow, threat model finalization) and design-questions.md (6 questions). Awaiting answers.

---

## U6 — Answers, Code Generation, Build & Test; Construction complete
**Timestamp**: 2026-11-18
**User Input**: "accept recommended defaults" (Q1–Q6)
**AI Response**: Escape suite (17 tests, canaries) found 2 defects, both fixed with regression tests: D1 host stack overflow from deep guest recursion (process crash → DoS; fixed via max_wasm_stack 1 MiB / async_stack_size 4 MiB); D2 unbounded input file count (cap 1000). Added CI escape-suite + perf-smoke jobs, release workflow (5 targets, per-target escape gate, attestations, draft release), final THREAT_MODEL.md, build-and-test summary. 103 tests + perf pass locally (release: 92 ms / 149 ms / 6 ms). Cleaned 182 MB of test scratch from C:. Awaiting final approval; Linux/macOS CI pending user check.

---

## CI feedback — supply-chain job
**Timestamp**: 2026-11-19
**User Input**: Screenshots of GitHub Actions: all `test` (4 OS), `escape suite` (4 OS) and `performance smoke` jobs green; `supply chain (cargo-deny + cargo-audit)` failed (only warnings visible in the screenshot).
**AI Response**: Reproduced locally with cargo-deny 0.21.0 (prebuilt, sha256-verified, installed to D:). Real errors: (1) wildcard path deps on publishable crates → all crates `publish = false`; (2) six RUSTSEC advisories against zip 2.x (extract/symlink/AES/stream reader; not reachable from our code, which reads only the pinned embedded zip via by_name/by_index+enclosed_name) → upgraded zip to 9.7, no code changes; (3) humantime unmaintained (RUSTSEC-2026-0542) → replaced with an in-crate RFC 3339 formatter + test; (4) chrono unmaintained (RUSTSEC-2026-0543), a required transitive dep of rmcp/schemars → scoped, documented ignore in deny.toml and .cargo/audit.toml. Removed unused license allowances (ISC, CDLA). Local: cargo deny all ok; clippy clean; all tests pass with the stdlib re-extracted by zip 9. NFR-1 and AC 1/10 confirmed on Linux x64/arm64 + macOS by the user's CI run.

---

## Cycle 1 — Final approval
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: U6 and Build & Test approved; AI-DLC cycle 1 (Phases 1–3) closed. Deferred to next cycle: OTLP exporter (R6), Phase 4 network broker (ADR-002), Phase 5 snapshots/pooling/sessions/benchmarks. Release is user-triggered via a `v*` tag (draft release for review).

---

# Cycle 2

## Cycle 2 start — Workspace Detection
**Timestamp**: 2026-11-19
**User Input**: "Now you can start cycle 2"
**AI Response**: Brownfield detected (clean tree, in sync with origin, ~11.6k lines of Rust). Reverse Engineering skipped (cycle-1 artifacts current). Issued aidlc-docs/cycle-2/inception/requirements/requirement-verification-questions.md (10 questions: scope, guest HTTP API, raw TCP, TLS trust, proxy, redirects, SSRF/private IPs, credential injection, OTLP scope, body logging).

---

## Cycle 2 — Requirements answers & draft
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults"
**AI Response**: Q1–Q10 = A. Generated cycle-2/inception/requirements/requirements.md: FR-N1..N11 (broker, transparent guest APIs, HTTP semantics, allowlist, SSRF/rebinding with IP pinning, quotas, raw TCP, OS trust store, operator proxy, audit without bodies, kill switch), FR-O1 (OTLP behind feature), NFR-N1..N6, 10 acceptance criteria. Awaiting approval.

---

## Cycle 2 — Requirements approved; Workflow Planning
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Generated cycle-2/inception/plans/execution-plan.md: Application Design + light Units Generation, 5 units (C2-U1 policy/config/audit ext, C2-U2 sandboxd-net broker, C2-U3 guest integration, C2-U4 OTLP, C2-U5 E-NET + CI). Awaiting approval.

---

## Cycle 2 — Workflow Planning approved; Application Design issued
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Research: reqwest 0.13.5 already in tree (via rmcp); its rustls default uses rustls-platform-verifier (OS trust store) and supports extra roots, custom Resolve, and redirect Policy::none. Generated cycle-2/inception/application-design/application-design.md (components, data flow, ADR-C2-1..6, threat additions T13–T18, R8) and design-questions.md (5 questions). Awaiting answers.

---

## Cycle 2 — Application Design answers; Units Generation
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults"
**AI Response**: Design Q1–Q5 = A. Generated cycle-2/inception/application-design/unit-of-work.md (C2-U1..U5 with gates; U1/U4 combined design+code gates; U2/U3 full flow). Awaiting approval.

---

## Cycle 2 — Units approved; C2-U1 built
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: C2-U1 (combined design+code): policy scheme/timeouts/kill switch/helper path, ensure_supported accepts grants, max_requests default 0→100 (latent defect), audit LimitKind::Network + net.request fields + net.connect, server [network] config, CLI wiring. 107 workspace tests pass, clippy clean. Summary: cycle-2/construction/c2-u1-policy-config-audit/design-and-summary.md. Awaiting approval.

---

## C2-U1 approved; C2-U2 design issued
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Confirmed reqwest 0.13 APIs (Resolve, remote_addr, chunk, tls_certs_merge, retry, Proxy/NoProxy). Generated cycle-2/construction/c2-u2-net-broker/design.md (URL rules U1–U6, allowlist, SSRF classes incl. metadata endpoints and IPv6 transition, pinning resolver, exchange H1–H7, device state machine, TCP, audit, API, tests) and design-questions.md (7 questions). Note: reqwest retries must be disabled (an un-audited retry is an extra request). Awaiting answers.

---

## C2-U2 — answers, code, build & test
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults" (Q1–Q7)
**AI Response**: Implemented sandboxd-net (ip, target, resolve, frame, http, tcp, lib) + VirtualDevice::opened / async VirtualFdTable::open. 26 broker tests (in-process HTTP/HTTPS-with-test-CA/TCP servers) pass; SSRF/redirect/header/quota/TLS/TCP cases verified with "server saw 0 requests". Fixed during implementation: reqwest retries disabled; system proxy never implicit; TLS error classification through io::Error::get_ref; ring provider (ADR-C2-1 amendment); ISC + CDLA re-allowed in deny.toml; feature-unification regression (rmcp client needed a crypto provider) fixed via ensure_crypto_provider(). Workspace 133 tests pass; clippy, fmt, cargo-deny clean. Awaiting approval.

---

## C2-U2 approved; C2-U3 design issued
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: C2-U2 marked approved (commit fe6d08a pushed). Probed the real guests: eager `import urllib.request` costs ~0.9 s (debug), so Python patching must be lazy (meta-path hook); CPython `open()` on a virtual fd fails (fd_filestat_get → EBADF), so the interposer gets a fix; QuickJS-ng has `qjs:os` and `-I/--include` but no TextEncoder/TextDecoder. Generated cycle-2/construction/c2-u3-guest-integration/design.md (launch lines, boot.py with frame trimming, lazy http.client/socket patches, device socket with synthesized responses, error mapping, /dev/sandbox/info for N2.3, boot.mjs fetch/Headers/Response, helper embedding + hash-keyed mount, runtime/binary wiring, test plan) and design-questions.md (8 questions). Proposed ADR-C2-3 amendment: JS uses `qjs -I`. Awaiting answers.

---

## C2-U3 — answers, code, build & test
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults" (Q1–Q8)
**AI Response**: Implemented guest helpers (sandboxd_boot.py, sandbox_net.py, boot.js, fetch.js), hash-keyed helper cache with in-sandbox .pyc compilation, /dev/sandbox/info, runtime broker wiring (RuntimeConfig.broker, LimitKind::Network, grants-without-broker refusal), VFS Helpers mount + fd_filestat_get on virtual fds + StaticDevice, binary broker/crypto-provider wiring; removed the NetworkBroker seam. Findings fixed: excepthook ignores tb (traceback trimming), half-built HTTPResponse on failure, qjs -I includes are classic scripts, JS method bug. NFR-N3: first version cost +31M fuel (Python) / +8.8M (JS); root cause for Python = first builtins.compile() initializes AST types (~22M); decision: Python bootstrap only when the policy grants network or code mentions networking modules, otherwise cycle-1 launch (final: 58.07M vs 58.03M baseline); JS lazy fetch.js (+1.4M). 19 new tests pass; all cycle-1 runtime/VFS/server tests and escape suite 17/17 pass; clippy, fmt, cargo-deny clean. One unreproduced flake (twenty_concurrent_runs, under parallel load) got better diagnostics. Awaiting approval.

---

## C2-U3 approved; C2-U4 built (combined gate); CI moved to Node 24
**Timestamp**: 2026-11-19
**User Input**: "approve"; mid-turn: "We are getting some warning regrading node 20, and it's batter to go with node 24"
**AI Response**: C2-U3 marked approved (commit 20c3ee6; push pending, GitHub unreachable from the session). C2-U4: `otel` feature (opentelemetry 0.33, OTLP/HTTP protobuf over the existing reqwest 0.13), mirrored metrics, `sandboxd.run` span without code/output/paths/principal, bounded shutdown, [telemetry] otlp_endpoint/otlp_interval validation, RunResult.net_requests, CI otel job (default build has 0 OpenTelemetry crates). Found: OTLP client needed a rustls provider (installed by Telemetry); stdlib cache could lose the empty lib-dynload dir → ensure_stdlib restores it. Node 24: FORCE_JAVASCRIPT_ACTIONS_TO_NODE24, actions/cache@v5, upload-artifact@v6, download-artifact@v7, rustsec/audit-check replaced by cargo-audit. All tests, clippy (both feature sets), fmt, cargo-deny pass. Summary: cycle-2/construction/c2-u4-otlp/design-and-summary.md. Awaiting approval.

---
