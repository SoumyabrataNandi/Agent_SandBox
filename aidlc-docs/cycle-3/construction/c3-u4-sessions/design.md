# C3-U4 Sessions — Functional Design

**Requirements:** FR-SE1 (SE1.1–SE1.8; SE1.2 amended by design Q4/Q5), NFR-P1 (session call ≤ 2 ms overhead), NFR-P2, AC 5–8 · **ADR:** ADR-C3-4

## 1. Model
A **session** is one live interpreter instance (one wasmtime `Store`) that serves a sequence of **calls**.
- **What persists:**
  - Python globals and imports, and JavaScript global declarations;
  - files in a session-private writable **`/work`** (counted against the artifact byte/file quota);
  - the network quotas (per session).
- **What doesn't:**
  - stdout/stderr (per call);
  - `/out` (collected and cleared after each call);
  - wall-clock and fuel budgets (per call).
- **Lifetime:** sessions live **in memory only** and end on `close`, idle timeout, lifetime, max calls, a CPU/wall-clock limit, or server shutdown.

## 2. Components
| Component | Responsibility |
|---|---|
| `sandboxd-runtime::SessionInstance` | Actor task owning `Store`, `Instance`, `RunFs` (+ `/work`) and `RunNet`. Receives `Call {code, args?, stdin?, files?, events}` on a channel, one at a time, and replies with a `RunResult`. |
| `/dev/sandbox/session` device | The guest loop's only input. A `read` blocks (async, host-side) until the next call, then returns a frame `{"cell": N, "path": "/code/cell_N.py"}`. The guest writes back `{"status": "ok" \| "error" \| "exit", "exit_code": n}`. |
| Guest loop: Python `sandboxd_session.py` | `compile(source, "/code/cell_N.py", "exec")` + `exec` in the persistent `__main__` dict. An exception prints CPython's traceback (bootstrap frames trimmed, as in C2-U3). `SystemExit` → status `exit` with its code, and the session continues (Q5 of the app design). |
| Guest loop: JS `session.mjs` | `std.evalScript(source, {async: true})`, awaited, so declarations persist and top-level `await` works. Errors are printed like `qjs` prints uncaught errors. |
| Per-call accounting | The host sets a **per-call deadline and fuel budget** in the store data before releasing the frame. The epoch callback (10 ms) checks both and traps on overrun. A trap ends the session (SE1.4), and the result says `limits_hit: wall_clock/cpu` + `session_ended: limit`. |
| Output rotation | stdout/stderr `CappedStream`s are re-armed per call (fresh buffer and cap); streaming events go to the current call's channel. |
| `sandboxd-server::SessionStore` | `id → handle {principal, policy, language, created, last_used, calls, expires_at}` plus the instance's channel. A reaper task (every 5 s) enforces `idle_ttl`, `max_lifetime` and `max_calls`. |
| HTTP | `POST /v1/sessions` · `POST /v1/sessions/{id}/runs` (body as `/v1/runs` minus language/policy; `?stream=true` supported) · `GET /v1/sessions/{id}` · `DELETE /v1/sessions/{id}` |
| MCP | `session_create {language, policy}` → `{session_id, expires_at}` · `run_code {…, session_id?}` · `session_close {session_id}` |
| Audit | `session.start {session_id, lang, policy}` / `session.end {session_id, reason, calls, duration_ms}`; every call's `run.start`/`run.end` carry `session_id` |
| Metrics | `sandboxd_sessions_active`, `sandboxd_session_calls_total`, `sandboxd_sessions_ended_total{reason}` (+ OTLP mirrors) |

## 3. Policy and limits
- `[session]`:
  - `enabled` (default false): a policy must opt in;
  - `idle_ttl` (default **10 min**);
  - **`max_lifetime`** (1 h);
  - **`max_calls`** (1000);
  - `max_sessions` (per policy, default 100).
- **Server-wide cap (Q3):** `[runtime] max_sessions` (default 16), because each session holds an instance and its memory. The pool is sized `max_concurrent + max_sessions + 2` (ADR-C3-3).
- **Admission:** a session call takes a normal admission permit for its duration, like a run.
- **Memory:** the policy's `memory` limit applies to the whole session. A guest `MemoryError` is a normal exception, and the session continues.

## 4. Security (threats T20, T23)
- Session ids are UUIDv4 (122 random bits), prefixed `ses_`. **Another principal gets `404 SESSION_NOT_FOUND`**, the same as an unknown id, so ids can't be probed. Every refused access is audited.
- **One call at a time per session (Q2).** A concurrent call gets `409 SESSION_BUSY`, deterministic for agents.
- `/work` is per session; `/in` gets the files sent at creation and with each call; `/out` is cleared per call; the code directory holds only the cell files. Nothing is shared between sessions.

## 5. Interpreter path (Q1)
- **Snapshot path:** a new `sandboxd-session` export in the custom interpreters (argv/env/per-run setup, then the helper loop) gives fast session creation with the preloaded modules. This needs one more interpreter release; the spike checks the export exists.
- **Upstream path:** `python -I -B -S -X frozen_modules=on -c "<launcher>" …` with `sandboxd_session.main()`, or `qjs --std -m -I boot.js /usr/local/lib/sandboxd/session.mjs`.
- The same memory-floor rule as runs applies.

## 6. Tests
- **State:** variables, imports, `/work` files and JS globals persist across calls; `/out` and output are per call; artifacts appear only in the call that produced them.
- **Errors:** an exception in a cell continues the session; `sys.exit(3)` returns exit 3 and the session continues; a wall-clock or CPU overrun ends the session (`session_ended: limit`), and a later call gets `404`.
- **Expiry:** idle, lifetime and max-calls each end the session with an audited reason (short test values).
- **Ownership:** a second principal gets `404`; an unknown id gets `404`; `max_sessions` (policy and server) → `429 SESSION_LIMIT`; a policy with `enabled = false` → `403 SESSIONS_DISABLED` at creation.
- **Concurrency:** two calls at once → one gets `409`.
- **Interfaces:** HTTP (incl. streaming) and MCP end to end; audit events; metrics.
- **Performance:** session call overhead measured against an equivalent one-shot run (target ≤ 2 ms, NFR-P1).
