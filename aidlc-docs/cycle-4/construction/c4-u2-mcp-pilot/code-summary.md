# C4-U2 MCP pilot — Summary

**Requirements:** FR-PL1 · **AC:** 3

## What was added
- **`scripts/pilot/mcp_pilot.py`** (standard library only, `python -I`): starts `sandboxd mcp` with a temporary config (temp cache/work/audit, plus a session-enabled `notebook` policy), does the MCP stdio handshake (`initialize` with protocol 2025-06-18, `notifications/initialized`), and runs 10 agent-shaped scenarios with explicit checks. It also fails on any non-JSON line on stdout (protocol pollution). Exit status is non-zero on any failure; `--json` writes results; the stderr tail is printed on failure.

| Scenario | Checks |
|---|---|
| handshake | `tools` capability; instructions mention the stdlib-only rule and `/out`; 4 tools; `run_code` schema has language/code/files/limits/session_id |
| policies | `default` and `notebook` listed (structured and text) |
| csv-analysis | CSV in `files` → `csv` + `statistics` aggregates are exact; `/out/report.md` comes back as an embedded resource with the right content |
| exception | exit code 1; the traceback names `main.py` line 2 and the `ValueError`; the summary says "exit code 1" |
| wall-clock-limit | `limits.wall_clock = 1s` on an infinite loop: outcome `limit`, `limits hit: wall_clock` in the summary, stopped in < 10 s |
| native-extension | `import numpy` → `UNSUPPORTED_NATIVE_EXTENSION` with guidance |
| javascript | `qjs:std` reads an `/in` JSON file; result correct |
| session | create on `notebook`; 3 cells share globals, an import and a `/work` file; close; a call to the closed session → `SESSION_NOT_FOUND` |
| progress-stream | with a progress token, progress notifications carry the stdout lines while the run executes |
| bad-input | unknown language and unknown policy are rejected (policy named in the error); the server keeps serving |

- **CI:** the `test` job runs the pilot on `ubuntu-latest` and `windows-latest` after the smoke step (reusing the debug build; cold cache), and appends the table to the job summary.

## Results (local, Windows, debug build)
- Cold cache: `initialize` answered after **65–68 s** (the cache and snapshots are built before serving). Warm: **0.3–0.4 s**. 10/10 pass.

## Findings
| # | Finding | Decision |
|---|---|---|
| F1 | **First start blocks `initialize` while caches and snapshots are built** (~20 s release per the benchmark's start-up row, ~65 s debug). Claude Code's default MCP connect timeout is about 30 s, so a first connection can time out. | **Fixed in docs (C4-U3):** install steps run `sandboxd cache warm` once (verified: it builds the snapshots too; the next `initialize` takes 0.4 s), and troubleshooting mentions `MCP_TIMEOUT`. A background-build `initialize` is a cycle 5 candidate. |
| F2 | A program that raises, or hits a limit, returns `isError: false`. | **Kept by design** (U5 design: `isError` only for service errors and traps; the tool worked, the program failed). The summary line ("outcome: exit, exit code 1" / "limits hit: wall_clock") and stderr make the failure explicit. The pilot asserts this contract. |
| F3 | (Pilot bug, not sandboxd) QuickJS `scriptArgs` includes the script name. | Pilot fixed. |

No sandboxd code changes were needed.
