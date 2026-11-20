# C3-U5 Benchmarks — Design & Code Summary (combined gate)

**Requirements:** FR-B1 (B1.1–B1.3), NFR-P1, AC 4 + AC 9 · **ADRs:** ADR-C3-5 (CI feedback channel), ADR-C3-6 (harness)

## Design
| Decision | Choice | Why |
|---|---|---|
| Harness | `scripts/bench/run.py`: Python stdlib only; drives the release binary and the Docker CLI. Writes one JSON results file, saved after every system so a partial run still publishes. | ADR-C3-6; no new dependencies |
| Renderer | `scripts/bench/render.py` turns a results file into `docs/BENCHMARKS.md`, including the NFR-P1 verdict table. `--none` renders methodology only (committed now as the placeholder). | B1.3: numbers are never typed by hand |
| Workflow | `.github/workflows/bench.yml`: `workflow_dispatch` (inputs: `iterations` = 200, `gvisor` = true), `ubuntu-latest`. Runs the harness self-test, builds release and pulls the images. Results go to the job summary, an artifact (JSON, rendered page, logs) and `ci-results` (`bench/<sha>.json`, `bench/latest.json`, `bench/latest.log`). `contents: write` only for that job. | ADR-C3-5: I read results with `git fetch`, no `gh` needed |
| sandboxd systems | **server with snapshots** and **server without snapshots** (HTTP on keep-alive connections, `max_concurrent` 16, pooling default, file audit sink, warm cache), plus the **CLI** (one process per run). | B1.2 |
| Container systems | `docker run --rm` (cold) and `docker exec` into a running container (warm), with `python:3.15-slim` and `node:22-slim`, `--network none`, read-only bind mounts. The same two systems run with gVisor `--runtime runsc` when it installs. | B1.2 |
| gVisor install | Latest release from Google's bucket, checked against its published SHA-512, `runsc install`, Docker restart, then a smoke run. Step is `continue-on-error`; the harness checks again and records "skipped: reason". | "if installable on the runner"; runner-only, nothing shipped |
| Scenarios | `print(1)` (Py), `console.log(1)` (JS), **1 MiB CSV** parse + aggregate → JSON (seeded, deterministic; expected output computed with the host CPython and checked on every run), **session calls** (Py/JS, `n += 1; print(n)`, state checked). | B1.1 |
| Latency | Warm-up (10), then N=200 sequential runs; `perf_counter_ns` around the whole client call. A wrong output counts as an error, not a sample. Nearest-rank p50/p95/p99. | B1.1 |
| Throughput | `hello-py` at concurrency 1/4/16 (thread pool, 200 runs per level, connections pre-warmed). | B1.1 |
| Memory | sandboxd: server RSS (`/proc`) delta for 8 idle Python sessions, and peak delta while 8 runs sleep concurrently. Containers: `docker stats` of 8 idle Python containers. Methods are labelled in the table. | B1.1, NFR-P1 idle session ≤ 40 MiB |
| NFR-P1 verdicts | p50 for the latency targets. Session overhead = end-to-end p50 of a trivial cell over HTTP (an upper bound: it includes HTTP and the guest work). Throughput = best concurrency level. Non-snapshot path: reported as the ratio to the snapshot path; regression is guarded by the CI perf smoke test. | AC 4 |
| Unavailable pieces | No Docker / no runsc / no `/proc` → recorded under "skipped" with the reason and shown in the page. | AC 9: "every comparator that ran" |

## Files
- `scripts/bench/run.py`, `scripts/bench/render.py`, `scripts/bench/test_bench.py` (7 self-tests: percentiles, CSV determinism, memory units, NFR verdicts, every page section, placeholder, CLI round trip).
- `.github/workflows/bench.yml`.
- `docs/BENCHMARKS.md`: generated placeholder (methodology, caveats); replaced by the rendered CI results.
- `README.md`: "Benchmarks" section linking the page.

## Verification so far
- Self-tests: 7/7.
- End-to-end on this laptop with the **debug** binary and Docker off, 10 samples: every sandboxd system and scenario ran with 0 errors. Docker/gVisor were skipped with reasons; memory was skipped (no `/proc` on Windows). Rendering worked. These numbers are not published; indicative only: snapshot Python 18 ms, JS 8 ms, session call 3 ms, CSV 0.4 s, no-snapshot Python 110 ms, CLI 0.43 s.
- **AC 4 / AC 9 need the CI run:** start Actions → bench → Run workflow. I then render `docs/BENCHMARKS.md` from `ci-results` and commit it.
