# C5-U2 Operator wheelhouse — Summary

**Requirements:** FR-PK1 (PK1.4/1.5 amended) · **Threats:** T24, R14 · **AC:** 3

## Design
- **Config:** `[packages] dir` and an optional `[packages] sha256` lock (64-hex values; a lock without `dir` is an error). The policy gets `[python] packages` (default `true`).
- **`sandboxd-runtime/src/packages.rs`:**
  - `scan()` validates without writing:
    - regular `.whl` files only (no symlinks), at most 1000 wheels;
    - PEP 427 file name with pure tags (`py3`/`py2.py3`, `none`, `any`);
    - strict lock when one is given (unlisted wheel, mismatch or missing file is an error);
    - zip entries: absolute/`..`/drive names and symlinks are refused; native suffixes (`.so`, `.pyd`, `.dll`, `.dylib`, including `.so.N`) are refused; `*.data/platlib` is refused; `*.data/purelib` is flattened; other `*.data` schemes are skipped;
    - at most 20 000 entries and 64 MiB uncompressed per wheel.
  - `prepare()` builds `<cache>/packages/<hash>/site` in a temp directory, then renames it with a marker. The directory holds a **copy of the guest helpers** (including `__pycache__`) plus the wheels. The hash covers the helpers' hash and the (file, sha256) list. Two wheels writing one file, or a wheel providing a helper's top-level name, is an error.
- **Why the helper directory (PK1.4 amendment):** the snapshot interpreter executes `/code/main.py` from C, and its `sys.path` was fixed when the snapshot was built: stdlib, then `/usr/local/lib/sandboxd`. Mounting the merged directory there makes packages importable on every path (snapshot, upstream, sessions) without rebuilding interpreters, and always after the stdlib. CPython's `FileFinder` rescans because the merged directory's mtime differs from the snapshot-time helpers directory.
- **Runtime:**
  - `Inner::helpers_for(lang, policy)` picks the merged or the plain helpers for one-shot runs and sessions;
  - upstream one-shot runs with packages use the boot launcher, which appends the helper dir (found by the tests: plain runs execute `main.py` directly);
  - package bytecode is compiled inside the sandbox (`compileall`, not fatal on failure);
  - `WarmupReport.packages` and `Sandbox::packages()` report the set.
- **Surfaces:**
  - `sandboxd packages list` validates the directory and prints a ready-to-paste lock;
  - start-up logs the wheel count and set hash;
  - `cache warm` prepares the packages too; `cache clear` removes them;
  - MCP instructions mention operator packages; `list_policies` lists them (text and structured).

## Tests
- Unit (7): wheel names; extract + reuse + helpers copied (without markers) + new helpers give a new directory; unsafe wheels (two native, traversal, absolute, platlib, junk zip), with nothing written outside; strict lock; overlapping wheels; wheels can't replace helpers (module or package).
- Integration `tests/packages.rs` (4):
  - snapshot path (verified by the `run.start` interpreter) and upstream path each check: import works; a `json` package in a wheel doesn't shadow the stdlib; the stdlib comes before the helper dir on `sys.path`; `__file__` is under the helper dir; writes to package files are refused; `[python] packages = false` opts out; JavaScript is unaffected;
  - sessions on both paths;
  - a native wheel stops start-up with a message naming it.
- Server config tests: `[packages]` parsing, bad hex, lock without dir, unknown key.
