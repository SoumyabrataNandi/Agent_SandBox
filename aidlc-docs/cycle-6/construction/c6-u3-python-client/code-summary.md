# C6-U3 Python client — Summary

**Requirements:** FR-CL1, FR-CL2 · **AC:** 1, 3

- **`clients/python` (`sandboxd-client`, module `sandboxd_client`, Python ≥ 3.10, standard library only, `py.typed`):**
  - `Sandboxd(url, token, timeout, retries)`, defaulting to `SANDBOXD_URL` / `SANDBOXD_TOKEN`. Its `repr` never shows the token.
  - `run` and `stream` (an iterator of `StreamEvent`; the last event is `result`). Text files are sent as is, bytes as base64.
  - `create_session` / `session(id)` return a `Session` with `run`, `stream`, `info` and `close`. As a context manager it closes on exit and ignores `SESSION_NOT_FOUND` if the session has already ended.
  - `policies`, `health`.
  - `RunResult` dataclass: every API field plus `ok`, `stdout_bytes`, `artifact(name)` and decoded `Artifact.content`.
- **Errors:** `SandboxdError(code, message, status)` comes from the server's error body. A non-JSON body maps to `HTTP_<status>`; no response maps to `UNREACHABLE`; an SSE `error` event raises. `429` is retried up to 3 times, honouring `Retry-After` (capped at 10 s).
- **SSE parser:** handles `event:` / `data:` lines, keep-alive comments and CRLF, ignores unknown events, and stops at `result`.
- **Tests (`clients/python/tests`):**
  - 7 unit tests on a stub server: headers and body, no auth header without a token, error mapping, the 429 retry, unreachable, stream parsing, token hiding.
  - 7 integration tests: health and policies; files (text, bytes, nested) with args, stdin and artifacts; JavaScript; exit, exception and limit as results; streaming; a session (state, stream, info, closed afterwards); refusals (401, 404, 400, `SESSIONS_DISABLED`).
- **`clients/testserver.py`:** starts `sandboxd serve` on a free port with a fresh token and a `notebook` policy, waits for `/healthz`, runs a command with the env set, then cleans up. It is shared by both clients.
- **Local results:** 14/14 against a real server (Python 3.13); the wheel builds, installs in a fresh venv and imports; the README example runs as written. CI runs the suite on Python 3.10.
- **`scripts/client_versions.py`:** checks (or `--set`s) the four client version strings against the workspace version.
