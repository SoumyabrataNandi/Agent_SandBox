# C3-U6 Escape Cases, Threat Model, Docs — Code Summary

**Requirements:** NFR-P2, AC 1/3/6/7/10 · **Threats:** T19–T23 (application-design §3)

## Escape suite: `tests/escape-suite/tests/cycle3.rs` (6 cases, release-blocking)
The world runs with snapshots **forced on** and pooling on, so a fallback can't hide a case. It uses two principals (`alice`, `bob`) over the HTTP router. Every probe looks for a fresh canary in globals, `sys.modules`, the `gc` heap (dict/sequence contents), the environment and every reachable file (`/`, `/tmp`, `/work`, `/out`, `/in`, `/code`). JavaScript probes check the global object. Each probe embeds its needle reversed and skips its own copy, so it can't find itself. **A positive control** (the planting session probes itself and must report a hit) proves the probe works.

| Case | Threat | What it proves |
|---|---|---|
| E-POOL-1 | T19 | 4 rounds × 8 concurrent tasks: Alice plants canaries (globals, 1 MiB+ heap, env, `/out`, `sys.modules`; JS globals) and Bob probes, in both languages, cycling every pool slot. Nothing is found. |
| E-SES-1 | T20 | Bob's GET/run/DELETE on Alice's session, and `/v1/runs` with her `session_id`, all get a 404 whose body is **identical** to an unknown id's. Alice's state is intact afterwards. Hostile ids (empty, zeros, upper-case, `%00`, `/../`, URL-encoded traversal, 8 KiB) never give a 5xx. Bob's probes are audited under his name. |
| E-SES-2 | T19/T20 | A planted session's canary (globals, `/work`, env, `sys.modules`, heap) is invisible to a live sibling session, a plain run, and three successor sessions after it closes (pool slot reuse). No host leftovers under the work dir. JS globals likewise. |
| E-SES-3 | T23 | `/dev/sandbox/session` can't be reopened. A cell that writes forged replies to fds 3–63 and then spins ends the session with `limit` within seconds (audited `session.end{reason=limit}`). Later calls get 404. |
| E-SNAP-1 | T21 | A snapshot `.cwasm` with a flipped byte, and one replaced by a different **valid** module, are both rebuilt (sidecars re-hashed) and runs are correct. |
| E-SNAP-2 | T22 | Host paths (cache, work and temp dirs, in both slash styles) and host env values (PATH, HOME/USERPROFILE, USER/USERNAME) are absent from a snapshot run. The run is verified to be on the `snapshot` interpreter. |

## Threat model
`THREAT_MODEL.md`:
- Header, assets and a new "Run ↔ run, session ↔ session" trust boundary.
- T19–T23 with mitigations and tests.
- Residual risks: R11 (a wasmtime pool-reset bug; `pooling = "off"` escape hatch), R12 (a session keeps one interpreter by design, single principal), R13 (budget granularity of 10 ms + 10 M fuel).

## Docs and packaging
- `README.md`: speed table updated (numbers deferred to `docs/BENCHMARKS.md`); new sections "Performance features (cycle 3)" (snapshots, pooling, sessions) and "Benchmarks"; the security-testing paragraph lists E-POOL/E-SES/E-SNAP.
- `docs/NETWORK.md`: in sessions, network quotas are per session, deadlines per call, and audit carries `run_id` + `session_id`.
- `docs/MCP.md`: sessions (done in C3-U4).
- `THIRD_PARTY_NOTICES.md`: the CPython and QuickJS-ng reactors and wasi-libc (wasi-sdk 33), with how they're built, pinned and attested.
- `release.yml`: release archives also ship `BENCHMARKS.md`. The snapshot interpreters are already embedded in the binary through `assets/manifest.toml`.

## Fixes found in this unit
- **`otel` feature build (CI failure on 67801fb):** `session_ended` used `KeyValue` unqualified, outside the module's otel-only import. The default build doesn't compile that block, so local checks missed it. Fixed by qualifying `opentelemetry::KeyValue`. Checked with the CI's otel clippy and test commands.
- **C3-U4 Linux test failure (b6ce2e9):** didn't reproduce. The next push (67801fb) passed `test` on ubuntu-latest and ubuntu-24.04-arm and the escape suite on all 4 OSes. Most likely the timing-bound flake noted in the C3-U4 commit. CI now publishes failing test output to `ci-results` (`ci/<sha>/<os>.log`), so the next failure can be diagnosed without the GitHub UI.

## Verification
- Escape suite: cycle3 6/6, escape 17/17, E-NET 11/11 (Windows, debug).
- `cargo clippy --workspace --all-targets -D warnings` clean; otel clippy + otel tests: see audit log.
