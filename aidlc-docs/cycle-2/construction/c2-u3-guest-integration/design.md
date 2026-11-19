# C2-U3 Guest Integration — Functional Design

**Unit:** C2-U3 · **Requirements:** FR-N2 (N2.1–N2.3), NFR-N3 (no-grant runs pay nothing measurable), NFR-N6 · **ADR:** ADR-C2-3 (amended below)
**Depends on:** C2-U1 (policy, audit), C2-U2 (`sandboxd-net` broker, devices)

## 1. Goal
Ordinary guest code reaches allowlisted hosts with no sandbox-specific changes:

| Language | Works unchanged | Transport |
|---|---|---|
| Python | `urllib.request.urlopen`, `http.client.HTTPConnection` / `HTTPSConnection`, `sandbox_net.fetch` | `/dev/sandbox/http` (HTTP rules) |
| Python | `socket.create_connection` (and code built on it), `sandbox_net.connect` | `/dev/sandbox/tcp/<host>:<port>` (TCP rules) |
| JavaScript | global `fetch`, `Headers`, `Response` | `/dev/sandbox/http` |

Everything else about a run stays the same as in cycle 1: `sys.argv`, `scriptArgs`, tracebacks (`File "/code/main.py", line N`), exit codes, stdout/stderr, the audit stream, and native-extension detection.

## 2. Findings that shaped the design (probed in the real guests)
| Probe | Result | Consequence |
|---|---|---|
| `import urllib.request` in guest CPython | ≈ 0.9 s (debug host); `socket` ≈ 85 ms | The bootstrap **must not import anything eagerly**. Patches are installed by a lazy import hook (§4.2). |
| CPython `open('/dev/sandbox/http')` | `FileIO` calls `fstat`, and the interposer forwards `fd_filestat_get` on a virtual fd to wasmtime-wasi, which returns `EBADF` | Interposer fix: `fd_filestat_get` on a virtual fd returns a character-device filestat (§6). The helpers use `os.open/os.read/os.write` anyway. |
| QuickJS-ng 0.18 WASI | `qjs:os` has `open/read/write/close`, `O_RDWR`. **No** `TextEncoder`/`TextDecoder`. `qjs` supports `-I/--include file` | `boot.mjs` carries a small UTF-8 codec. The JS bootstrap uses `-I` instead of wrapping the program (ADR amendment, Q1). |
| `ssl` in guest CPython | absent, so `http.client.HTTPSConnection` doesn't exist | The shim provides `HTTPSConnection`; TLS is done by the broker (Q2). |

## 3. Launch lines
| Language | Cycle 1 | Cycle 2 |
|---|---|---|
| Python (bootstrap) | `python -I -B -S -X frozen_modules=on /code/main.py <args>` | `python -I -B -S -X frozen_modules=on -c "<launcher>" /code/main.py <args>`, where the launcher is `import sys;sys.path.insert(0,'/usr/local/lib/sandboxd');import sandboxd_boot;del sys.path[0];sandboxd_boot.main()` |
| Python (plain) | | unchanged from cycle 1 (see below) |
| JavaScript | `qjs -m /code/main.mjs <args>` | `qjs --std -m -I /usr/local/lib/sandboxd/boot.js /code/main.mjs <args>` |

**Implementation findings (NFR-N3), measured with fuel (deterministic instruction counts):**
- The first design (`boot.py` as the script) cost **+31 M fuel** for Python `print(1)` (58 M → 89 M) and **+8.8 M** for JS `console.log` (2.4 M → 11.2 M).
- Precompiling the Python helpers to `__pycache__` with the bundled interpreter at start-up (the same in-sandbox `compileall` used for the stdlib; marker keyed by the CPython asset hash) and importing them from a one-line `-c` launcher removed the bootstrap's own compile. **But** the bootstrap must still `compile()` `/code/main.py` itself, and CPython's first Python-level `compile()` builds every AST node type (`PyAST_Check` → `init_types`): **~22 M fuel** that a native script launch never pays. No traceback-preserving alternative exists (`exec(str)` labels code `<string>`; `-S` disables `sitecustomize`; `-X presite` is debug-build only).
- **Decision:** Python uses the bootstrap only when the policy grants network access **or** the program text mentions a networking module (`socket`, `urllib`, `http`, `sandbox_net`, `asyncio`, `smtplib`, `ftplib`, `imaplib`, `poplib`, `nntplib`, `xmlrpc`, `__import__`, `importlib`), i.e. whenever N2.3's clear error can matter. Everything else launches **exactly as in cycle 1**, at zero cost. This is not a security boundary: without grants there are no network devices whichever line is used. The only gap: a deliberately obfuscated import under a no-grant policy gets WASI's generic socket error rather than the policy message.
- JavaScript: `boot.js` is a ~40-line stub. `fetch`/`Headers`/`Response` are lazy getters, and the implementation (`fetch.js`) is read with `std.loadFile` and evaluated on first use. `--std` is needed for a synchronous file read in a classic script; the stub captures `std`/`os` and **deletes** the `std`/`os`/`bjson` globals before the program runs. Result: **+1.4 M fuel** (< 1 ms) per JS run.

## 4. Python

### 4.1 `sandboxd_boot.main()` (module imports only `sys`; loaded from `.pyc`)
1. `sys.argv = sys.argv[1:]` (`['-c', '/code/main.py', *args]` → `['/code/main.py', *args]`), exactly as in cycle 1.
2. `sys.path.append('/usr/local/lib/sandboxd')`, so `import sandbox_net` works. `/code` is still not on `sys.path` (`-I` implies `-P`), as in cycle 1.
3. Insert `_LazyPatcher` at the front of `sys.meta_path` (§4.2).
4. Read `/code/main.py` as bytes and `compile(src, '/code/main.py', 'exec', dont_inherit=True)`. Create a fresh `__main__` module (`__file__`, `__builtins__`, `__spec__ = None`), put it in `sys.modules['__main__']`, and `exec` the code in its dict.
5. **Uncaught exceptions** (not `SystemExit`): drop the leading traceback entries whose `co_filename` is `sandboxd_boot.py`, call `sys.excepthook(type, exc, trimmed_tb)`, and exit with status 1, which is what CPython does. A `SyntaxError` in `main.py` trims to an empty traceback and prints exactly as in cycle 1, with no `Traceback` header. `SystemExit` propagates unchanged, so `sys.exit(n)` behaves the same.
6. Not hidden (documented): `inspect.stack()` and `sys._getframe()` from user code will see one bootstrap frame below `<module>`, and `sys.orig_argv` shows the real launch line.

### 4.2 Lazy patching (NFR-N3)
`_LazyPatcher.find_spec(name, …)` only reacts to `http.client` and `socket`. It asks the remaining finders for the spec and wraps `spec.loader.exec_module`, so the patch runs immediately after the stdlib module body. Nothing is imported until the program itself imports one of these modules. If a target module is already in `sys.modules`, it is patched at once. The hook removes itself after both modules have been patched. Programs that never touch networking normally don't use the bootstrap at all (§3).

| Module loaded | Patch (in `sandbox_net`) |
|---|---|
| `http.client` | `HTTPConnection.connect` installs a `_DeviceSocket` instead of a TCP socket. `HTTPSConnection` is defined (or replaced) as a subclass with port 443 that accepts and ignores `context=`/`check_hostname=`. `_create_https_context` is stubbed if missing, so urllib's default `HTTPSHandler` can be built. `set_tunnel` raises `PermissionError` (guest proxies are refused: E-NET "guest attempts to use a proxy"). |
| `socket` | `socket.create_connection` → `sandbox_net.connect(host, port, timeout)`. |

`urllib.request` needs no patch of its own: `urllib.request` imports `http.client` before it defines its handlers, so the default `HTTPHandler`/`HTTPSHandler` use the patched classes. Its own redirect handler sees only final responses, because the broker follows redirects (ADR-C2-2). One wrapper is added when `urllib.request` loads (Q3): `AbstractHTTPHandler.do_open` re-raises an `OSError` from `getresponse` as `URLError(err)`, as urllib already does for connect errors.

### 4.3 `_DeviceSocket`: HTTP over the device
http.client writes a normal HTTP/1.1 request into the socket. `_DeviceSocket` buffers `sendall`/`send`. When the response is requested it:
0. (the exchange runs in the patched `getresponse`, *before* `HTTPResponse` is constructed, so a failure never leaves a half-built response object behind; `makefile` then just returns the bytes)
1. parses the buffered request: request line and headers, and the body by `Content-Length` or chunked encoding. An **absolute-form target** (`GET http://…`) means a proxy request → `PermissionError`;
2. builds the URL: `scheme://host[:port]` from the connection, plus the origin-form target;
3. performs one device exchange (§4.5);
4. returns `io.BytesIO` holding a **synthesized HTTP/1.1 response**: the status line with `http.HTTPStatus` phrase, the broker headers minus `Content-Length`/`Transfer-Encoding`/`Connection`, then `Content-Length: n`, `Connection: close` and the body. The real `http.client.HTTPResponse` parses it, so `read(n)`, `readline`, `getheader`, `HTTPMessage`, iteration and `HEAD` handling are exactly the stdlib's. `Connection: close` makes http.client reconnect, with a fresh `_DeviceSocket`, for the next request on the same connection object.

The final URL after broker-followed redirects is kept on the connection, and urllib's response `.url`/`geturl()` reports it.

### 4.4 `sandbox_net` public API
```python
fetch(url, method="GET", headers=None, body=None, timeout=None) -> Response
    # Response: .status .reason .headers (case-insensitive, multi-value) .body (bytes)
    #           .url (final) .redirects .ok  .text(encoding=None) .json()
    # 4xx/5xx are returned, not raised (like requests).
connect(host, port, timeout=None) -> Connection
    # socket-like: send sendall recv recv_into makefile close shutdown settimeout
    # gettimeout setblocking setsockopt(no-op) getpeername fileno(-1) context manager
```

### 4.5 Device I/O and error mapping
`fd = os.open('/dev/sandbox/http', os.O_RDWR)`; write the frame; read until EOF; close. Frame-error codes from the broker map to **built-in** exceptions carrying a `.code` attribute (Q4):

| Broker code | Python | JS (`fetch` rejects with) |
|---|---|---|
| `DENIED`, `SSRF`, `NETWORK_DISABLED` | `PermissionError` | `TypeError` |
| `TIMEOUT` | `TimeoutError` | `TypeError` (`cause.code = "TIMEOUT"`) |
| `DNS` | `socket.gaierror` (imported only on this path) | `TypeError` |
| `CONNECT`, `TLS` | `ConnectionError` | `TypeError` |
| `QUOTA`, `RESPONSE_TOO_LARGE`, `TOO_MANY_REDIRECTS`, `PROTOCOL` | `OSError` | `TypeError` |

Every message is the broker's message, e.g. `PermissionError: http://10.0.0.5/ is not allowed: no rule matches host 10.0.0.5`. In JS, `TypeError("fetch failed: <message>", { cause: { code, message } })` follows the WHATWG pattern (network errors are `TypeError`).

TCP (`/dev/sandbox/tcp/<host>:<port>`): `open` errno → `EACCES` → `PermissionError("connection to db:5432 is not allowed by the sandbox network policy (see the audit log)")`. Also `ECONNREFUSED` → `ConnectionRefusedError`, `ETIMEDOUT` → `TimeoutError`, `ENOENT` → `socket.gaierror`. `read`/`write`: `ETIMEDOUT` → `TimeoutError`, `EIO` (quota) → `OSError("network byte quota exhausted")`, others → `ConnectionResetError`/`BrokenPipeError`.

### 4.6 No-grant runs (N2.3)
Without grants the broker returns no `RunNet`, so `/dev/sandbox/http` and `/dev/sandbox/tcp/…` don't exist (`ENOENT`). To tell "no grant" apart from a DNS failure and to name the policy, the runtime always registers a tiny read-only **`/dev/sandbox/info`** device (Q5). It returns `{"policy":"default","http":false,"tcp":false}` and is opened only on a failure path. The resulting message is:
`PermissionError: network access is not allowed by policy 'default'` (Python) / `TypeError: network access is not allowed by policy 'default'` (JS).
Only the policy name and two booleans are exposed. Rules, hosts and quotas are not.

## 5. JavaScript `boot.js`
Loaded with `-I`. **Implementation finding:** QuickJS evaluates `-I` includes as *classic scripts* even with `-m`, so a static `import` is a syntax error. The bootstrap is therefore `boot.js`: one closure (no global bindings leak), which loads `qjs:os` with a dynamic `import()` that `fetch` awaits. `scriptArgs` and the program's stack traces are unchanged. It defines, non-enumerable on `globalThis`:
- `fetch(input, init)`: `input` is a string, an object with `.url`, or a `Request`-like object. `init` takes `method`, `headers` (object, array of pairs, or `Headers`), `body` (string, `ArrayBuffer`, typed array/`DataView`), and `redirect` (only `"follow"` is supported). `signal` is not supported. `fetch` returns a `Promise<Response>`. The device call is synchronous inside the promise executor; QuickJS has no host event loop for it, so `fetch` blocks the single guest thread for the request's duration (documented).
- `Headers`: case-insensitive; `get` (multi-values joined with `", "`), `has`, `set`, `append`, `delete`, `forEach`, `entries`, `keys`, `values`, iterator.
- `Response`: `status`, `statusText`, `ok`, `headers`, `url`, `redirected`, `bodyUsed`, `text()`, `json()`, `arrayBuffer()`, `bytes()`. A body can be read once.
- A UTF-8 encoder/decoder (WHATWG replacement-character semantics) used for frame headers and `text()`.
- `qjs:os` is imported by `boot.js` only; no `os`/`std` globals appear, and the program's own imports are unaffected.

## 6. Host side

| Component | Change |
|---|---|
| `sandboxd-runtime/guest/` (Q6) | `boot.py`, `sandbox_net.py`, `boot.js` embedded with `include_str!` |
| `sandboxd-runtime::helpers` | `ensure_helpers(cache_dir) -> PathBuf`: `cache_dir/helpers/<sha256 of all helper bytes>/`, extracted to a temp sibling and atomically renamed, with a marker file (the same pattern as the stdlib, ADR-004). A changed helper changes the hash, so stale copies are never used. |
| `sandboxd-vfs::RunFs` | `with_helpers(host_dir)` adds a read-only `MountKind::Helpers` mount at `HELPER_GUEST_PATH`. Its reads are summarized like stdlib reads (no per-file audit noise), and its ancestors are quiet probes. |
| `sandboxd-vfs::interposer` | `fd_filestat_get` on a virtual fd returns a `CharacterDevice` filestat (size 0). |
| `sandboxd-vfs::StaticDevice` | Read-only bytes device (used for `info`) |
| `sandboxd-runtime::RuntimeConfig` | `broker: Option<Arc<sandboxd_net::Broker>>` |
| `sandboxd-runtime::run` | After policy tightening: `broker.for_run(&policy, RunCtx { run_id, policy, deadline, audit })`. `Some(net)` → `net.register(&mut vfds)`; `info` is always registered. After the run, `net.finish().limit_hit` → `LimitKind::Network` in `limits_hit`, and the outcome becomes `limit` (§5 classification, as for other limits). **A policy with grants but no broker** → `RunError::PolicyViolation("this policy grants network access, but network access is not configured on this runtime")`, and the guest never starts (Q7). |
| `sandboxd-runtime::seams` | The unused cycle-1 `NetworkBroker` trait is removed; the concrete `sandboxd_net::Broker` replaces it (Q8). |
| `sandboxd` binary | `ensure_crypto_provider()` first in `main`. `BrokerConfig` comes from `ServerConfig.network` (`extra_ca_file` read and validated at start; a bad file → startup error). `[network] enabled = false` → no broker (policies with grants are already refused at load by C2-U1). |
| Deadline | The broker deadline is the same `Instant` as the epoch deadline, so network time counts against `wall_clock` (N1.2). |

## 7. Security notes (feeds the C2-U5 threat model)
- The helpers are read-only, hash-keyed and outside every writable mount. A guest can monkey-patch its *own* copy of `sandbox_net` in memory, but that only changes what it sends to the device, and every request is still enforced host-side. **No security decision is made in the guest.**
- The `info` device reveals the policy name and whether HTTP/TCP is granted, nothing else.
- Guest proxy use (`set_tunnel`, absolute-form targets, `*_proxy` env from the policy) is refused in the shim. It is also unreachable host-side, because a proxy host would need its own allowlist rule.

## 8. Error-message and compatibility contract (tests)
1. `print(1/0)` → stderr is byte-identical to cycle 1 (`Traceback …`, `File "/code/main.py", line 1, in <module>`, `ZeroDivisionError`), exit 1.
2. `SyntaxError` → identical to cycle 1.
3. `sys.exit(3)` → exit 3. `sys.argv == ['/code/main.py', 'a', 'b']`.
4. `import numpy` → `UNSUPPORTED_NATIVE_EXTENSION` still detected.
5. JS `throw new Error('x')` → same stderr as cycle 1. `scriptArgs` unchanged.

## 9. Test plan
**Runtime integration tests** (real CPython and QuickJS, with in-process axum HTTP, an HTTPS server using an rcgen CA passed as `extra_ca_pem`, and a TCP echo server; policies use `allow_private_ips = true` for the positive cases):
- Python: `urllib.request.urlopen` GET/POST (+ JSON), `http.client.HTTPConnection` and `HTTPSConnection`, `HTTPError` on 404, `sandbox_net.fetch`, `socket.create_connection` echo, `http.client` over a redirect (final URL), proxy attempt refused, denial → `URLError(PermissionError)` / `PermissionError`, timeout → `TimeoutError`.
- JS: `fetch` GET/POST, `json()`, `Headers`, 404 `ok == false`, denial → `TypeError`, UTF-8 round trip.
- No-grant policy: both languages give `… not allowed by policy 'default'`, and the target server saw **0 requests**.
- Quota → `limits_hit` contains `network`, outcome `limit`.
- Grants without a broker → `POLICY_VIOLATION`, the guest never runs.
- The §8 compatibility contract. All cycle-1 runtime tests still pass.
- **NFR-N3:** hello-world latency with the bootstrap vs. cycle 1 (release perf test), recorded in the code summary. Target: no measurable difference beyond noise (≤ ~5 % or ≤ 2 ms).

**Unit tests:** helper extraction (hash keying, repair of a corrupted cache), `StaticDevice`, `fd_filestat_get` on a virtual fd.

## 10. ADR-C2-3 amendment (Q1 = A)
JavaScript uses `qjs -m -I boot.js /code/main.mjs` (a classic script; see §5) instead of `boot.mjs` + `await import('/code/main.mjs')`. `-I` evaluates the bootstrap before the program, so no bootstrap frames appear in stack traces and `scriptArgs` doesn't need fixing.
