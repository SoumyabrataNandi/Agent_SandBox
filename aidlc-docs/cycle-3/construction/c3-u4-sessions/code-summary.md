# C3-U4 Sessions — Code Summary

**Requirements:** FR-SE1, NFR-P1, AC 5–8 · **Design:** `design.md` (answers: all A) · **ADR:** ADR-C3-4

## What was built
| Area | Change |
|---|---|
| Interpreters | `sandboxd-session` export in both reactors (release `interp-0bb2fe9cb3da6365`, pinned in `assets/manifest.toml`). |
| Guest | `sandboxd_session.py` / `session.mjs`: loop over `/dev/sandbox/session`; frame `{cell, path, args}` → reply `{status, exit_code}`; EOF ends. Exceptions and `sys.exit(n)` end the call, not the session. |
| Policy | `[session]` gains `max_lifetime` (1 h; 1 min–24 h) and `max_calls` (1000); `idle_ttl` default 10 min; `enabled = true` is accepted; `explain` shows the settings. |
| VFS | `/work` mount (`MountKind::Work`, live quota shared with `/out`, never collected); `QuotaHandle` (reset per call to the bytes/files already in `/work`); `CallIds` (per-call run id + session id on fs audit events); `RunFs::{with_code_dir, write_code, with_work, work_usage, add_inputs, clear_outputs}`. |
| Network | `RunCtx.session_id`; `RunNet::begin_call(run_id, deadline)`: per-call deadline and run id, quotas per session. |
| Runtime | `session.rs`: `Sandbox::open_session`, `Session::{call, close, info}`, `SessionOptions`, `CallRequest`, `CallOutcome`, `SessionEnd`, `SessionError`. Actor task owns the `Store`; one call at a time (`Busy`); `max_calls`/`max_lifetime` enforced at call time; slot held for the session's life. |
| Audit | `session.start` / `session.end {reason, calls, duration_ms}`; every call's `run.start`/`run.end`, fs, net and limit events carry `session_id`. |
| Server | `SessionStore` (reservation-based caps: server-wide `[runtime] max_sessions` = 16, per-policy `max_sessions`); reaper every 5 s (idle, lifetime); `close_all_sessions` on shutdown; pool slots = `max_concurrent + max_sessions + 2`. |
| HTTP | `POST /v1/sessions` (201) · `POST /v1/sessions/{id}/runs[?stream=true]` · `GET`/`DELETE /v1/sessions/{id}`; `/v1/runs` with `session_id` routes to the session. Errors: `SESSION_NOT_FOUND` 404 (also for other principals), `SESSION_BUSY` 409, `SESSION_LIMIT` 429, `SESSIONS_DISABLED` 403. |
| MCP | `session_create`, `session_close`, `run_code {session_id}` (language/policy checked against the session); instructions updated. |
| Metrics | `sandboxd_sessions_active`, `sandboxd_session_calls_total`, `sandboxd_sessions_ended_total{reason}` + OTLP mirrors. |
| Docs | `docs/MCP.md` "Sessions" section and `[runtime] max_sessions`. |

## Per-call budgets (how and what we found)
The guest loop is one long wasm call, so the store's fuel can't be refilled per call (hook/epoch
callbacks get read-only store access). Instead the store gets ~unlimited fuel and `CallCtl` tracks
consumption: a call hook arms the budget when the guest returns from the read that **delivered**
the frame and samples fuel at every host call; the epoch callback checks fuel and the deadline
every tick. Two defects found by tests and fixed:
1. **Stale fuel in hot loops.** Compiled code keeps the fuel counter in a register; a loop without
   calls never writes it back, so the CPU budget never fired (Python `while True: pass` ran to the
   wall clock). Fix: `fuel_async_yield_interval(10M)` makes the guest sync it every ~2 ms. A 50 M
   budget now stops at ~57 M fuel.
2. **Budget armed by the host, not the guest.** A cell that forges the loop's reply (the device fd
   is guessable) and keeps spinning got the *next* call's full budget. Fix: only the device marks a
   generation delivered; until then the **idle guard** (200 M fuel between calls) applies, and the
   session ends on a CPU limit within milliseconds.

## Limitations
- **No stdin in session calls.** wasmtime's p1 stdin adapter treats EOF as permanent. Callers send
  data as a file under `/in`, and the request is refused with a clear message.
- **Limit overrides in a call.** A call can only tighten `wall_clock` and `fuel`. The other limits
  are fixed when the session is created.
- **Enforcement granularity.** Budgets are enforced to within one epoch tick (10 ms) plus 10 M fuel.
- **Sessions live in memory only.** A restart ends them, by design.

## Tests
- Runtime `tests/session.rs` (12): state persists (Python/JS, snapshot and upstream), exceptions and
  `sys.exit` continue, `/work` persists, `/out` per call, guest exit, CPU/wall-clock limits end the
  session (busy loops in both languages), forged reply, validation, Busy/max_calls, audit ids,
  call overhead (Windows debug ≈ 4–7 ms/call; NFR-P1's 2 ms target is measured in C3-U5 on Linux
  release).
- Server `tests/sessions.rs` (4): HTTP lifecycle, ownership (404 + audited), SSE, `/v1/runs` routing,
  metrics; caps (403/429), busy (409), stdin refused, limit ends the session; idle reaper; MCP tools.
- Policy: `sessions_are_supported_and_validated`; config: `[runtime] max_sessions`.
