# U6 Escape Suite + Release — Design

**Goal:** prove the isolation claims adversarially (NFR-4, AC 4, 5, 10), make them release-blocking on all three OSes (NFR-1), ship binaries, and finalize `THREAT_MODEL.md` so that every threat links to a test.

## 1. Escape suite (`tests/escape-suite`, Q1)
A black-box test crate. It drives `RunService` in-process and the real `sandboxd` binary, and never calls internals. Each case declares **the attack**, **the expected containment**, and **the expected audit evidence**. A case fails if *any* of the following happens:
- host data leaks into stdout, stderr or artifacts (canary strings planted on the host);
- the outcome isn't the expected one;
- the sandbox process crashes or becomes unhealthy afterwards;
- an expected audit event is missing.

| ID | Threat | Attack cases (Python and, where relevant, JS) | Expected |
|---|---|---|---|
| E-FS-1 | T1 traversal | `../`, `sub/../../`, absolute `/etc/passwd`, Windows forms (`C:\\Windows\\win.ini`, `\\\\?\\C:\\`, `..\\`), NUL in path, 4 KiB path, URL-encoded `%2e%2e` | Denied; canary not read; `fs.access deny` for host-reaching attempts |
| E-FS-2 | T1 symlinks | Host-side symlink inside a ro mount pointing outside (Unix CI); guest `os.symlink('/etc','/out/x')` then read `/out/x/passwd`; guest symlink to `..` | Not followed outside the preopen (cap-std); symlink not collected as an artifact |
| E-FS-3 | T1 hard links / rename | `os.link` from a ro mount into `/out`; rename across mounts; rename `/out` itself | Refused (EPERM / EXDEV / denied) |
| E-FS-4 | T1 write protection | Write/append/truncate/unlink/chmod on `/in`, `/code`, the stdlib, ro mounts, `/` | Refused; files unchanged on host |
| E-FS-5 | Info leak | `os.listdir('/')`, `os.getcwd()`, `sys.path`, `sys.executable`, tracebacks | No host paths, usernames or drive letters in output |
| E-ENV | T2 | `os.environ`, JS `std.getenviron()`; a host canary env var set in the test process | Only policy env vars visible; canary absent |
| E-CPU | T3 | `while True`, catastrophic regex `(a+)+$`, `sum(range(10**12))`, JS `for(;;)`, busy loop in a `finally` after a caught exception | `cpu` or `wall_clock` within limit + tolerance |
| E-MEM | T4 | `bytearray(2**31)`, list doubling, string doubling, JS array growth, deep recursion (`sys.setrecursionlimit(10**6)`) | `memory` limit or a contained trap; host RSS stable; next run OK |
| E-OUT | T5 | stdout flood, stderr flood, `/out` big file, 10k small files, deep dir nesting, filename tricks (`..`, very long names) | Caps enforced live; collection bounded; CLI writes only inside `--out` |
| E-PROC | Process/network | `os.system`, `subprocess.run`, `os.fork`, `socket.socket().connect`, `urllib.request.urlopen`, `threading.Thread().start()`, `ctypes`, JS `os.exec` | Fails inside the guest; no host process spawned; no egress |
| E-POL | T6 | Limits above policy via API/MCP/CLI; unknown policy; policy name `../x`; mounts via request (no such field → 400) | Refused; `policy.denied` audited |
| E-AUTH | T7 | No token, wrong scheme, token in query string, token differing by one char, very long header, MCP without token | 401; nothing executed; tokens never appear in the audit log |
| E-INPUT | Request abuse | Input names `../x`, `/abs`, `CON`, `a/../../b`, duplicates differing in case, 10k files, invalid base64, body over the limit | 400 / 413 before anything touches disk |
| E-CRASH | T9 | 30 concurrent hostile runs (mixed above), then a normal run | All contained; service healthy; normal run OK; no leftover run dirs |
| E-AUDIT | T10-ish | Secrets in code / stderr / file names with `log_code = true` | Redacted in the audit log |

**Canaries:** the suite creates host files and an env var whose content is a random token (`CANARY-<uuid>`) and asserts that this token never appears in any output, artifact or audit line.

## 2. CI (release gate)
- `ci.yml` adds an **`escape-suite`** job on the same 4 runners (ubuntu x64/arm64, macOS, Windows), and a module cache keyed by asset hash + wasmtime version. It's a required check.
- A `perf-smoke` job (Q4) runs a release build on ubuntu-latest and checks `print(1)` ≤ 2× the NFR-3 target (600 ms) and `console.log` ≤ 100 ms, to avoid flakiness. It prints the calibration table.
- `cargo-deny` and `cargo-audit` are already in place.

## 3. Release workflow (`release.yml`, Q2/Q3/Q6)
- **Trigger:** a `v*` tag.
- **Build matrix:** `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`. Assets are fetched and verified first.
- **Gates:** each job runs the escape suite against its binary before packaging, with all target tests on the native runners. A cross-compiled Intel mac is tested on its native runner.
- **Package:** `sandboxd-<ver>-<target>.{tar.gz,zip}` containing the binary, LICENSE, NOTICE, THIRD_PARTY_NOTICES.md, README and docs/MCP.md, plus CPython's `LICENSE` extracted from the asset.
- **Publish:** a **draft** GitHub Release with `SHA256SUMS` and build-provenance attestation.

## 4. Threat model
`THREAT_MODEL.md` is finalized: assets, adversaries, trust boundaries, and a threat register **T1–T12 → escape-suite IDs**, plus residual risks and their owners:
- WASI/wasmtime bugs (mitigated by pinning and upgrading);
- Spectre-class side channels (out of scope);
- the cache-dir trust assumption (U4);
- rw policy mounts (operator responsibility);
- raw TCP opacity (Phase 4);
- no OTLP yet.

## 5. NFR
- The suite must run in under 5 minutes per OS in CI.
- Tests are deterministic, with time bounds of about 30% tolerance for CI noise.
- Canaries are cleaned up.
