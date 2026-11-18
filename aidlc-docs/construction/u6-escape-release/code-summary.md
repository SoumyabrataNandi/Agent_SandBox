# U6 Escape Suite + Release — Code Summary & Results (2026-11-18)

Design answers Q1–Q6: all recommended (dedicated black-box crate; 5 release targets; draft release on `v*` tags; 2× NFR-3 perf smoke; OTLP deferred; SHA256SUMS + build provenance).

| File | Content |
|---|---|
| `tests/escape-suite/tests/escape.rs` | 17 adversarial tests across 15 families (E-FS-1…E-AUDIT). The hostile world plants random canaries on the host (outside mounts, in symlink targets) and asserts they never appear in output, artifacts or audit lines. Every case also asserts no `ESCAPED` marker, the expected containment, and service health afterwards. |
| `crates/sandboxd-runtime/tests/perf.rs` | Release-mode perf smoke (ignored by default; run in CI) |
| `.github/workflows/ci.yml` | `test` (4 OS) → required **`escape-suite`** job (4 OS) + `perf-smoke` + supply chain |
| `.github/workflows/release.yml` | `v*` tag → 5 targets; **escape suite runs per target before packaging**; archives with licenses; build-provenance attestation; draft GitHub Release with `SHA256SUMS` |
| `THREAT_MODEL.md` | Final: T1–T12 each mapped to tests; residual risks R1–R7 with owners |

## Defects found by the escape suite (both fixed, with regression tests)
| # | Severity | Finding | Fix |
|---|---|---|---|
| **D1** | **High (DoS)** | Deep guest recursion (`sys.setrecursionlimit(10**6)` + recursive function) **overflowed the host fiber stack and crashed the whole `sandboxd` process**, killing every concurrent run. Cause: U4 set `max_wasm_stack` = 2 MiB = the default `async_stack_size`, which left no headroom for host calls made from deep in the guest stack. | `max_wasm_stack(1 MiB)` + `async_stack_size(4 MiB)` (~3 MiB host headroom). Regression test `deep_recursion_is_contained_not_a_host_crash` in the runtime crate, plus E-MEM / E-CRASH. |
| **D2** | Medium (disk DoS) | No cap on the **number** of request input files: 10k one-byte files fit `input_bytes` but each became a host file/dir. | `MAX_INPUT_FILES = 1000` in `RunFs`, checked before disk. Covered by E-INPUT. |

Test-harness fixes: per-test run-dir checks (other tests share the world and run in parallel); a fixed, self-cleaning scratch dir for the suite (earlier it leaked about 5 MB per run on the system temp drive).

## Results (Windows host, local)
- **Escape suite: 17/17 pass** in about 17 s (parallel, `--test-threads=4`).
- **Perf smoke (release):** CPython `print(1)` **92 ms**, `import json,csv,re,datetime` **149 ms**, QuickJS `console.log` **6 ms**. All within NFR-3 (300 ms / 50 ms) and well within the 2× CI bounds.
- Workspace: **103 tests** (86 + 17 escape) + 1 perf. fmt and clippy `-D warnings` are clean.

## Not verifiable locally
- Linux/macOS CI runs, including the Unix-only symlink cases in E-FS-2 (R7), and the release workflow. These need the GitHub Actions run; see the build-and-test summary.
