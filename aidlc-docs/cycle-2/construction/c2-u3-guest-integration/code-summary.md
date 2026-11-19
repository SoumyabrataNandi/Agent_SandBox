# C2-U3 Guest Integration — Code Summary & Test Results

Design answers Q1–Q8: all recommended (JS `qjs -I` include; patch `http.client` so urllib, http.client and HTTPS all use the HTTP device; stdlib-shaped `URLError`; built-in exceptions with `.code`; `/dev/sandbox/info`; helpers in `crates/sandboxd-runtime/guest/`; grants without a broker are refused; the unused `NetworkBroker` seam is removed).

## What was built
| Area | Files | Content |
|---|---|---|
| Python bootstrap | `guest/sandboxd_boot.py` | `main()`: `sys.argv` fix-up, a lazy meta-path patcher for `http.client` / `urllib.request` / `socket`, runs `/code/main.py` as a fresh `__main__`, trims its own frames from uncaught-exception tracebacks, exit 1. Imports only `sys`. |
| Python network shims | `guest/sandbox_net.py` | `fetch()` → `Response`/`Headers`. `connect()` → socket-like `Connection` (`send`/`sendall`/`recv`/`recv_into`/`makefile`/…). `http.client` patch: a `_DeviceSocket` buffers the request; the exchange runs in `getresponse`; a synthesized HTTP/1.1 response is parsed by the real `HTTPResponse`. `HTTPSConnection` is provided (WASI has no `ssl`), with a stub TLS context for urllib. Proxy use (`set_tunnel`, absolute-form targets, `ProxyHandler`) is refused. urllib errors are `URLError(reason=<built-in>)`. `socket.create_connection` uses the TCP device. |
| JS bootstrap | `guest/boot.js`, `guest/fetch.js` | `boot.js`: a ~40-line stub. It deletes the `std`/`os`/`bjson` globals that `--std` created and installs lazy `fetch`/`Headers`/`Response`. `fetch.js` (evaluated on first use): WHATWG-style `fetch`, `Headers` (case-insensitive, sorted, `getSetCookie`), `Response` (`text`/`json`/`arrayBuffer`/`bytes`/`clone`, single use), and a UTF-8 codec. |
| Helper cache | `src/helpers.rs`, `src/cache.rs` | Embedded with `include_str!`. Extracted to `cache/helpers/<sha256>/` (atomic rename, marker, content verification, repair). The Python helpers are compiled to `__pycache__` in-sandbox at start-up (shared `compileall` runner with the stdlib; marker = CPython asset hash). `python_needs_bootstrap()`. |
| Runtime | `src/sandbox.rs`, `src/seams.rs`, `src/lib.rs` | `RuntimeConfig.broker`. `/dev/sandbox/info` (policy name + `http`/`tcp` booleans only). `Broker::for_run` with the run's deadline, and device registration. `LimitKind::Network` in results. Grants without a broker → `POLICY_VIOLATION`, guest never starts. New launch lines. `NetworkBroker` seam removed. |
| VFS | `interposer.rs`, `runfs.rs`, `vfd.rs` | `MountKind::Helpers` (read-only, reads summarized into one audit event). `RunFs::with_helpers`. `fd_filestat_get` on virtual fds (CPython `open()` on a device works). `StaticDevice`. |
| Binary | `crates/sandboxd/src/main.rs` | `ensure_crypto_provider()` first in `main`. Broker built from `[network]` (`extra_ca_file` read and validated at start; `enabled = false` → no broker). `cache clear` also removes `helpers`. |

## Launch lines (final)
| Run | Command |
|---|---|
| Python, plain (no grants, program doesn't mention networking) | `python -I -B -S -X frozen_modules=on /code/main.py …`, **identical to cycle 1** |
| Python, bootstrap | `python -I -B -S -X frozen_modules=on -c "<launcher>" /code/main.py …` |
| JavaScript | `qjs --std -m -I /usr/local/lib/sandboxd/boot.js /code/main.mjs …` |

## Findings during implementation (design §2/§3 updated)
1. **CPython's `open()` on a virtual fd failed** (`fd_filestat_get` → `EBADF`). Fixed in the interposer.
2. **Bootstrap frames leaked into tracebacks:** since 3.12 the default `sys.excepthook` ignores its `tb` argument. The trimmed traceback is now set on the exception itself. Tests compare tracebacks **byte for byte** with cycle 1.
3. **A failed exchange left a half-built `HTTPResponse`** ("Exception ignored while finalizing…"). The exchange now runs in `getresponse` before the response object exists.
4. **QuickJS evaluates `-I` includes as classic scripts** even with `-m`, so the JS bootstrap is a classic-script closure.
5. **JS `fetch(url)` sent method `FALSE`** (`isObj && input.method` evaluated to `false`, which is not nullish). Fixed.
6. **NFR-N3 (no measurable cost without the network).** The first version cost +31 M fuel per Python run and +8.8 M per JS run. Root causes and fixes:
   - Compiling the bootstrap from source every run → `.pyc` helpers + `-c` launcher.
   - Parsing ~450 lines of JS every run → lazy `fetch.js`.
   - CPython's first Python-level `compile()` builds every AST type (~22 M fuel) and is unavoidable inside a bootstrap → **plain Python runs skip the bootstrap**. It is used when the policy grants network access, or the code mentions a networking module, which keeps N2.3's clear errors where they can matter. This is not a security boundary: without grants there are no network devices.
7. **Remaining gap (documented):** a deliberately obfuscated import (e.g. `getattr(__builtins__, 'imp'+'ort')`) under a no-grant policy gets WASI's generic socket error instead of "not allowed by policy". This affects only error clarity; nothing can reach the network.

## Tests
**New: 19** (14 runtime integration + 5 unit), all against real CPython 3.15 / QuickJS-ng with in-process HTTP, HTTPS (test CA) and TCP servers. No internet access.

| Test | Proves |
|---|---|
| urllib GET/POST/redirect/HTTPError | stdlib urllib unchanged: JSON body and headers reach the server, `geturl()` is the final URL after a broker-followed redirect, 404 → `HTTPError` with body |
| http.client reuse + HEAD | 2 requests on one `HTTPConnection` (reconnect after `Connection: close`), `reason`, multi-headers, HEAD → empty body |
| HTTPS (urllib, `HTTPSConnection`, `fetch`) | TLS by the broker with the extra CA; `fetch` returns status, text, headers and the final URL |
| socket / `connect` | `create_connection` echo, `makefile("rwb")`, `recv_into` with UTF-8; both TCP sessions audited as `net.connect` |
| denials | Disallowed path → `URLError(PermissionError, code DENIED)`; disallowed method; `set_tunnel`; `ProxyHandler`; raw TCP under an HTTP-only policy (precise message); request timeout → `URLError(TimeoutError)` in < 2.5 s with outcome `limit`/`network`. **Server saw only the one allowed request; TCP server saw 0.** |
| quota | `max_requests = 1`: the second request → `OSError` code QUOTA; outcome `limit`, `limits_hit` contains `network` |
| JS fetch | GET/POST, `json()`, `Headers` multi-value, UTF-8 round trip (`héllo ✓ 😀`), binary body, redirect (`redirected`, final `url`), 404 `ok=false`, denial → `TypeError` with `cause.code`. **No `os`/`std` globals leak.** |
| JS HTTPS | `fetch` over TLS with the test CA |
| no grant | Python urllib / `sandbox_net` and JS `fetch` → "network access is not allowed by policy 'default'"; no `sandboxd_boot.py` frames; **server saw 0 requests** |
| no broker | Granting policy → `POLICY_VIOLATION`, no output; a plain policy runs on the same runtime |
| invisibility | Python traceback and SyntaxError byte-identical to cycle 1; `sys.argv`, `__name__`, `__file__`, `sys.path`; `sys.exit(3)`; JS error stack unchanged |
| bootstrap selection | Plain no-grant program → no bootstrap; mentions networking / granting policy → bootstrap. Fuel difference asserted. |
| devices | Plain `open('/dev/sandbox/info','rb')` works; info exposes only `policy`, `http`, `tcp` |
| quiet audit | Plain runs: no net events; helper reads summarized (≤ 1 event) |
| unit | Helper extraction/reuse/repair; LF line endings; launcher paths under the reserved path; bootstrap heuristic; `StaticDevice` |

**Regression:** all 20 cycle-1 runtime tests, the 10 VFS tests, the server/CLI tests and the **escape suite (17/17)** pass unchanged.

**Workspace:** clippy `-D warnings` and fmt clean. `--locked` ok. cargo-deny: advisories, bans, licenses and sources ok, with no new dependencies (test-only: axum, rcgen, rustls, tokio-rustls, serde, already in the lockfile).

**Flake observed once:** `twenty_concurrent_runs` (a cycle-1 test, plain programs on the unchanged launch line) failed once with empty output in a full-workspace run that overlapped a parallel cargo-deny compile. It did not reproduce in 12 further runs. Its assertion now reports outcome, error, limits and run time, so a recurrence in CI will be diagnosable.

## NFR-N3 performance (release, this laptop)
Fuel = executed WebAssembly instructions, which is deterministic, so it's the reliable metric. On this laptop wall time varies ±35 ms between identical runs.

| Workload (no network) | C2-U2 baseline fuel | First C2-U3 version | **Final** | Final best ms (baseline) |
|---|---|---|---|---|
| python `print(1)` | 58.03 M | 89.08 M (+53 %) | **58.07 M (+0.06 %)** | 102 (102–153) |
| python `import json,csv,re,datetime` | 138.23 M | 171.07 M (+24 %) | **138.60 M (+0.3 %)** | 167 (177–299) |
| javascript `console.log` | 2.40 M | 11.19 M | **3.77 M (+1.4 M, < 1 ms)** | 8 (8–16) |

Python runs without networking are back to the cycle-1 cost; the small residue is the helper mount and the `info` device registration. JavaScript pays for the ~40-line stub only. Network runs use the bootstrap; the broker's own per-request overhead is in the C2-U2 summary (0.36–0.54 ms). The CI perf-smoke bounds (2× NFR-3) still pass by a wide margin.
