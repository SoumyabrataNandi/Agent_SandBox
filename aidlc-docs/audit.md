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

## C2-U4 approved; C2-U5 built
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: C2-U4 marked approved (0b67631 pushed). C2-U5: E-NET escape family (11 cases, 10 in-process servers incl. 6 canary-serving forbidden destinations with hit counters; Py + JS) covering every NFR-N1 item plus raw device frames, shim tampering and concurrent isolation; THREAT_MODEL T13–T18, network trust boundary, R6 closed, R8–R10 added; docs/NETWORK.md (rules, limits, proxy guidance, APIs, error codes, audit); README and release packaging updated. Policy env keys must be uppercase (proxy policy uses HTTP(S)_PROXY). Escape suite 17 + 11, workspace tests, clippy (both feature sets), fmt, cargo-deny pass. AC 1–10 mapped in cycle-2/construction/c2-u5-enet-release/summary.md; AC 10 on CI runners pending the GitHub run. Awaiting approval.

---

## C2-U5 approved; cycle 2 closed
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: C2-U5 marked approved (f0036df). Wrote cycle-2/construction/build-and-test/build-and-test-summary.md (builds, 166 tests incl. 11 E-NET, performance, AC 1–10 evidence, defects fixed, carry-forward). Cycle 2 (Phase 4 network broker + OTLP) closed; GitHub Actions run of f0036df is the CI confirmation for AC 10 (not observable from this session). Repaired the mangled Toolchain line in aidlc-state.md. Next: cycle 3 (Phase 5 performance) from requirements.

---

## Cycle 3 started — workspace detection + requirements questions
**Timestamp**: 2026-11-19
**User Input**: "start cycle 3"
**AI Response**: Workspace detection: brownfield, clean tree (cce4125); reverse engineering skipped (artifacts current). Researched feasibility: Wizer (now wasmtime-wizer) pre-initialization gives ~1–5 ms CPython executions in other projects but requires an exported init function, so custom CPython/QuickJS WASI builds are needed; wasmtime pooling allocator supported on all OSes (CoW mainly Linux). Generated cycle-3/inception/requirements/requirement-verification-questions.md (10 questions: scope with snapshot spike gate, snapshot production, interpreter build hosting, pooling, session model/limits/API, Docker benchmarks, targets, behaviour guarantees). Awaiting answers.

---

## Cycle 3 — requirements answered; requirements.md issued
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults"
**AI Response**: Q1–Q10 = A. Generated cycle-3/inception/requirements/requirements.md: FR-P1 pooling, FR-S1 snapshots (S1.0 spike gate with exit criteria; CI-built pinned interpreters published as repo releases; Wizer at start-up; per-run restore; behaviour guarantees), FR-SE1 sessions (live instance, /work, policy keys incl. new max_lifetime/max_calls, idle_ttl default 5→10 min, ownership NOT_FOUND, HTTP+MCP API, audit), FR-B1 Docker benchmarks (bench.yml, docs/BENCHMARKS.md), NFR-P1..P6, AC 1–10. Awaiting approval.

---

## Cycle 3 — requirements approved; workflow plan issued
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Requirements approved. Generated cycle-3/inception/plans/execution-plan.md: change impact (high security impact: pooling/sessions/snapshots could leak state), stage decisions (App Design + light Infra Design execute; RE/User Stories skip), 6 preliminary units (U1 snapshot spike with go/no-go gate in CI, U2 pooling, U3 snapshot integration, U4 sessions, U5 benchmarks, U6 escape/threat model/docs), order U1∥U2 → U3 → U4 → U5 → U6, CI-feedback note (no gh CLI). Awaiting approval.

---

## Cycle 3 — workflow plan approved; application design issued
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Verified: wasmtime-wizer 50.0.2 exists (MSRV 1.97); wasi-libc __wasilibc_reset_preopens / __wasilibc_deinitialize_environ exist; CPython WASI build links extension modules statically. Generated cycle-3/inception/application-design/application-design.md (component changes; ADR-C3-1 reactor interpreters with wizer-initialize/sandboxd-run/sandboxd-session exports and native PyRun; ADR-C3-2 snapshots at start-up via wasmtime-wizer, memory floor, hash secret; ADR-C3-3 pool sizing; ADR-C3-4 sessions: actor-owned Store, device guest loop, per-call accounting in epoch callback; ADR-C3-5 ci-results branch; ADR-C3-6 bench harness; T19–T23) and design-questions.md (8 questions; Q1 amends S1.5, Q4 amends SE1.2). Awaiting answers.

---

## Cycle 3 — design answered; units generated
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults"
**AI Response**: Design Q1–Q8 = A. Amended requirements S1.5 (per-snapshot-build random hash secret; random re-seeded per run) and SE1.2 (cell_<N> files; sys.exit ends the call). Generated cycle-3/inception/application-design/unit-of-work.md: C3-U1 snapshot spike (CI-only, go/no-go), U2 pooling, U3 snapshot integration (if go), U4 sessions, U5 benchmarks, U6 escape/threat model/docs; order and CI round-trip mechanics. Awaiting approval.

---

## Cycle 3 — units approved; C3-U1 spike built
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: Verified wasmtime-wizer 50.0.2 calls the reactor `_initialize` before the init func and strips it from the snapshot (no double-init trap); its `run(store, wasm, instantiate)` takes our own WASI store. C3-U1: interpreters/sources.toml (pins; spike mode records digests), interpreters/build.sh (pinned wasi-sdk 33 + wasmtime CLI host runner, CPython `Tools/wasm/wasi build`, relink libpython with sandboxd_python.c using the Makefile's own flags; QuickJS-ng via CMake), sandboxd_python.c (reactor: wizer-initialize with -I -S -B frozen config + preload list + patched network shims in a private namespace, then reset preopens/environ; sandboxd-run: argv, posix.environ refill, random reseed, tzset, native PyRun_SimpleFileExFlags, finalize), sandboxd_qjs.c, tools/spike-snapshot (Wizer pre-init + byte-for-byte compat vs upstream on 10 Python / 5 JS programs + random-reseed check + timing/fuel; JSON report), .github/workflows/interpreters.yml (publishes report incl. build-log tails to orphan ci-results branch). Local: builds, clippy, cargo-deny clean. Pushed to trigger CI.

---

## C3-U1 first CI run; C3-U2 built
**Timestamp**: 2026-11-19
**User Input**: (none; session resumed with "continue")
**AI Response**: Spike run 1 (6e60851): CPython build step "cancelled" during the build-python configure (not a build error); report published to ci-results with digests of wasi-sdk 33, wasmtime CLI 50.0.2 and CPython 3.15.2, now pinned in interpreters/sources.toml (TOFU from CI; to be cross-checked against upstream-published digests before C3-U3). C3-U2 pooling: PoolingMode auto/on/off + pool_slots, PoolingAllocationConfig (default 4 GiB slots; tables 6005/595 fit the 20k default), probe instantiation at warm-up, Auto fallback, slot semaphore (wait, never fail), pool gauges (Prometheus + OTLP), [runtime] pooling config. Tests: 200-instance memory-reset check, slots released, 8 runs on 2 slots, fallback/on/off, config parsing; all suites + escape (17+11) pass with pooling on by default; clippy clean. Summary: cycle-3/construction/c3-u2-pooling/design-and-summary.md. Awaiting approval.

---

## C3-U2 approved
**Timestamp**: 2026-11-19
**User Input**: "approve"
**AI Response**: C3-U2 marked approved (a76ef15). Waiting for spike run 2 (a76ef15) report on ci-results.

---

## Repository made public; spike cancellations explained
**Timestamp**: 2026-11-19
**User Input**: "Ok make it public now" / "I make it public alreadyt"
**AI Response**: Pre-publication scan: no secrets in files or history (only redactor test fixtures); flagged personal details (commit author email, verbatim audit quotes, host description). User switched the repo to public (verified via anonymous API: visibility public). Actions API annotations show the spike and ci runs were "canceled by @SoumyabrataNandi" ~15–20 s after start, not by GitHub. Re-triggering the spike; asked the user to let runs finish (public repos have free Actions minutes).

---

## C3-U1 spike run 4 (5501ab1)
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: First complete run. Both reactors built (CPython 32 MB unstripped; QuickJS). JavaScript snapshot: 5/5 programs byte-identical; console.log(1) 65k vs 3.63M fuel (55x fewer instructions), 0.49 vs 1.15 ms (2.4x). Python: wizer-initialize exited 70 in the preload step (Python error text not captured). Fixes: link with PY_CORE_LDFLAGS (WASI stack/memory flags were missing; PY_LDFLAGS was empty) + --strip-debug; spike tool captures init stdout/stderr. Re-running.

---

## C3-U1 spike run 5 (b29941e)
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Python snapshot initialises and is compatible: 10/10 programs byte-identical (tracebacks, SyntaxError, sys.exit, argv/env, __main__, workload, atexit, chained, files); random re-seeded per run; snapshot built in 4.2 s (17 MB). But only 1.6x faster (77.6M vs 120M fuel). Causes identified in our harness/entry, not the approach: Py_FinalizeEx per run (full teardown of ~30 MB preloaded state); unfair baseline (CI stdlib had no bytecode); no pooling/CoW in the spike engine. Fixes: sandboxd-run uses PyRun_FileExFlags + CPython SystemExit rules + atexit + flushes, no Py_FinalizeEx; spike precompiles stdlib and uses the pooling engine. Re-running.

---

## C3-U1 spike run 6 (104d42e)
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Python 10/10 compatible; print(1) 4.02 vs 18.31 ms (4.56x), 11.5M vs 54.7M fuel (fair baseline with stdlib bytecode, pooled engine). JS 5/5 compatible, 0.30 vs 0.87 ms (2.9x), 65k vs 3.6M fuel. Next: gc.collect()+gc.freeze() at the end of wizer-initialize so per-run GC never rescans the preloaded objects. Re-running.

---

## C3-U1 spike run 7 (fb47a29)
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: gc.freeze() did not change the snapshot run's fuel (11.48M; 4.5x wall), so GC is not the cost. Added a `sandboxd-step` diagnostic export (argv, environ, per-run setup, run file, exit effects) and a per-phase fuel profile in the spike report. Re-running.

---

## C3-U1 spike run 8 (26ea50d): phase profile
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Phases of a restored print(1) run: argv 6.7k, environ 13k, per-run setup 0.98M, run file 0.24M, exit effects 0.48M (total ~1.72M) vs 11.48M for the whole run: ~9.8M is wasi-libc exit() (C atexit handlers/destructors). sandboxd-run now ends with _Exit(status) after the Python-visible exit effects. Re-running.

---

## C3-U1 spike run 9 (bb604e4)
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Report says go=true (5.04x wall), but fuel unchanged (11.47M), so the crossing is runner noise and the _Exit hypothesis was wrong; not accepted as a go. Phase measurements start after instantiation, so the ~9.8M gap is likely execution during instantiation (start function / memory init). Added instantiate fuel, module export shape and raw section listing (start/data sections) to the report. Re-running.

---

## C3-U1 spike run 10 (7a5c005): root cause found
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Instantiation of the snapshot costs 9.75M fuel ~= its 9.82 MB data section; no start section. wasmtime 50 initialises data segments with a compiled startup function (fuel-charged) unless the memory has a copy-on-write image, and only builds the image when the initialised range is dense or <= memory_guaranteed_dense_image_size (default 16 MiB). Wizer snapshots are large sparse heaps, so every instantiation copied all data. Set memory_guaranteed_dense_image_size(128 MiB) in the spike engine and in sandboxd's runtime engine (production snapshots need it). Re-running.

---

## C3-U1 spike run 11 (4dfeabb): exit criteria met
**Timestamp**: 2026-11-19
**User Input**: (none)
**AI Response**: Python print(1) 1.83 ms vs 29.2 ms (16x), 1.73M vs 54.8M fuel (32x), instantiation 0 fuel; 10/10 byte-identical; random re-seeded. JavaScript 0.41 vs 1.06 ms (2.6x), 65k vs 3.63M fuel, 5/5 identical. Local runtime suites pass with the new engine setting. Summary: cycle-3/construction/c3-u1-snapshot-spike/spike-summary.md. Recommending GO; awaiting the user's decision.

---

## C3-U1 decision: GO
**Timestamp**: 2026-11-19
**User Input**: "go"
**AI Response**: Spike accepted; FR-S1 proceeds. Starting C3-U3 design.

---

## C3-U3 design issued
**Timestamp**: 2026-11-19
**User Input**: (follows "go")
**AI Response**: Generated cycle-3/construction/c3-u3-snapshots/design.md (asset release pipeline gated on spike go, release-mode pins + upstream digest cross-check, embedded snapshot-capable interpreters, Wizer at start-up with cache/sidecar/fallback, run path table, memory floor, `interpreter` audit field, [runtime] snapshots, tests incl. Windows CoW measurement) and design-questions.md (5 questions). Awaiting answers.

---

## C3-U3 answers; release pipeline
**Timestamp**: 2026-11-19
**User Input**: "accept recommended defaults"
**AI Response**: Q1–Q5 = A. Cross-checked pins: wasi-sdk 33 and wasmtime 50.0.2 equal GitHub's published asset digests; CPython 3.15.2 equals python.org's published sha256; QuickJS is a GitHub tag archive without an upstream digest (pinned from CI, documented). Release mode for all builds; sandboxd-step compiled out unless SANDBOXD_SPIKE; spike job exports go + source hash; new `release` job (push + go only) publishes `interp-<hash>` (prerelease) with SHA256SUMS and provenance attestations.

---

## C3-U3: first integration findings (2026-11-20)
**Timestamp**: 2026-11-20
**User Input**: (session resumed with "continue")
**AI Response**: Release interp-f940919f383c1ce8 published (spike go in release mode) and pinned locally. Runtime snapshot integration built; snapshot tests pass (12 Python + 5 JS programs identical on both paths; no state carried between runs; per-language floors python 40 MiB, js 1.3 MiB equal what the upstream interpreters need; Windows: no CoW image, Python 26.9M vs 58.1M fuel). Full suites on the snapshot path found two interpreter bugs: (1) Python preload imported urllib.request before http.client was patched, so HTTPSHandler was never defined (NameError in build_opener); (2) QuickJS sandboxd-run never re-initialised `environ` after init reset it, so std.getenviron() crashed (E-ENV). Fixed both in the C entry points; added environ checks to the spike and parity tests. Pushing interpreter fixes alone to publish a corrected release before pinning.

---

## C3-U3 built and tested
**Timestamp**: 2026-11-20
**User Input**: (none)
**AI Response**: Corrected release interp-ef9ab1d314d38dc0 (spike go: Python 14.5x, JS 2.5x, compat incl. environ) pinned. All suites pass on the snapshot path: workspace (runtime 20, network 14, pool 6, snapshot 5, server, CLI, VFS, broker, audit, policy) and escape 17 + E-NET 11. Windows release perf: Python print(1) 31 ms (was 102–153), import-heavy 27 ms (was 167–299), JS 12 ms; no CoW on Windows (26.9M fuel). Summary: cycle-3/construction/c3-u3-snapshots/code-summary.md. Awaiting approval.

---

## C3-U3 approved
**Timestamp**: 2026-11-20
**User Input**: "approve"
**AI Response**: C3-U3 marked approved. Commit b849cc8 not yet on GitHub (push hangs: likely a Git Credential Manager sign-in prompt). Starting C3-U4 sessions design.

---

## C3-U4 design issued
**Timestamp**: 2026-11-20
**User Input**: (follows "approve")
**AI Response**: C3-U3 pushed (9e3ab22). Generated cycle-3/construction/c3-u4-sessions/design.md (session model, actor-owned Store, /dev/sandbox/session device + Python/JS guest loops, per-call accounting in the epoch callback, output rotation, /work, SessionStore + reaper, HTTP/MCP/audit/metrics, policy and server caps, security, interpreter path, tests) and design-questions.md (5 questions). Awaiting answers.

---

## C3-U4 answers; session guest loops + interpreter export
**Timestamp**: 2026-11-20
**User Input**: "accept recommended defaults"
**AI Response**: Q1–Q5 = A. CI run for 9e3ab22 (C3-U3) was again "canceled by @SoumyabrataNandi" ~4 min in (only supply-chain finished); told the user. Added guest session loops (sandboxd_session.py, session.mjs; device protocol {cell,path,args} → {status,exit_code}, EOF ends), sandboxd_boot.install_patcher(), and a `sandboxd-session` export in both custom interpreters; spike now reports snapshot exports. Pushing to build the interpreter release; host session engine next.

---

---

## C3-U4 construction; approval
**Timestamp**: 2026-11-20
**User Input**: "approve"
**AI Response**: Pinned interpreter release interp-0bb2fe9cb3da6365 (adds `sandboxd-session`; digests match SHA256SUMS and GitHub). Built the session engine (runtime `session.rs`: actor-owned Store, session device, per-call fuel/deadline via call hook + epoch callback, idle guard, per-call run ids in fs/net audit), policy `[session]` max_lifetime/max_calls, server SessionStore + reaper, HTTP `/v1/sessions*`, MCP `session_create`/`session_close`/`run_code session_id`, `[runtime] max_sessions`, metrics, docs/MCP.md. Approval received before the test run; commit follows once build and test suites pass (failures will be reported, not committed over).

---

## C3-U4 verification and commit
**Timestamp**: 2026-11-20
**User Input**: (follows "approve")
**AI Response**: Tests found and fixed three defects: (1) output buffers cleared before being read; (2) stale fuel in hot loops, so the per-call CPU budget never fired (fixed with fuel_async_yield_interval 10M); (3) a forged reply let the next call's budget arm early (budgets now arm only when the device delivers the frame; idle guard otherwise). Results: runtime session 12/12, server sessions 4/4, all other workspace suites green incl. escape 17 + E-NET 11; clippy clean. One one-shot timing assertion (ac2_wall_clock_busy_loop, end-to-end < 2.5 s) missed under full-workspace parallel load and passed on its own. Wrote code-summary.md; committing C3-U4.
