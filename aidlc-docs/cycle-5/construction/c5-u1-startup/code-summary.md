# C5-U1 Non-blocking MCP start-up — Summary

**Requirements:** FR-ST1 · **AC:** 1, 2 · Fixes cycle 4 pilot finding F1.

## Design
- `SandboxMcp` holds a `ServiceSlot`: either `Ready(RunService)` (HTTP `/mcp`, tests) or `Starting(watch::Receiver<Option<Result<RunService, String>>>)`.
- `SandboxMcp::deferred(transport) -> (SandboxMcp, StartupHandle)`. `StartupHandle::ready(service)` / `failed(reason)`; dropping it fails waiting calls instead of hanging them.
- Every tool (`run_code`, `list_policies`, `session_create`, `session_close`) first awaits `ready()`. With a progress token, a waiting call sends one progress notification ("sandboxd is starting (building the interpreter cache)…"). On failure: `isError` with `STARTUP_FAILED: sandboxd could not start: <reason>`.
- `sandboxd mcp` serves stdio immediately and builds the stack in a spawned task (emitting the `server.start` audit event when ready, and printing a start-up error to stderr). When the client disconnects, it waits for the build task to finish, then shuts down as before (sessions closed, `server.stop`, audit flushed, telemetry). A failed build makes the process exit non-zero.
- The HTTP server is unchanged: it binds only when ready, so `/healthz` stays a true readiness probe.

## Tests
- `st1_deferred_startup_waits_then_runs`: handshake and `tools/list` complete with no sandbox; a progress-token call waits (still pending after 300 ms) and receives the "starting" progress; after `ready()`, it returns the run's output; later calls go straight through.
- `st1_startup_failure_is_reported`: `run_code`, `list_policies` and `session_create` all return `STARTUP_FAILED` with the reason; a dropped handle doesn't hang calls.
- Pilot: a new `fast-initialize` check (`--max-initialize`, default 10 s) runs in CI on Linux and Windows with a cold cache; tool calls may wait up to 900 s for the first build.
