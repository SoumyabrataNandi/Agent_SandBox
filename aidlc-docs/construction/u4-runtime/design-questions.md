# U4 Runtime — Design Questions

Design: `design.md`. Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — Compiled-module cache
Compiling `python.wasm` takes about 5.4 s. Loading a cached `.cwasm` takes 7 ms, but `Module::deserialize` is `unsafe`, because a tampered file could run arbitrary host code.
A) **Disk cache with integrity check.** `.cwasm` plus a SHA-256 sidecar, verified before every deserialize. The key includes the engine compatibility hash and the cache dir is user-only. A single reviewed `unsafe` block **(Recommended; otherwise every `sandboxd run` CLI call takes 5–7 s)**
B) No disk cache: compile in memory at process start (safe, but 5–7 s startup for every CLI invocation and every server start)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Precompiled stdlib bytecode
Without `.pyc`, `import json, csv, re, datetime` costs about 430 ms, because CPython compiles stdlib sources on every run.
A) **At cache provisioning, run `compileall` inside the sandbox itself** (CPython WASI against a temporary writable copy of the stdlib). The `.pyc` files land in the hash-keyed cache, which is then mounted read-only. It's a one-time cost of about 20–40 s on first use, with no host Python needed **(Recommended)**
B) Accept the import cost for now and do it in Phase 5
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Native-extension detection (FR-1.5)
A) **After the run:** detect `ModuleNotFoundError: No module named 'numpy'` (etc.) for a known list → `UNSUPPORTED_NATIVE_EXTENSION{module}`, still returning stdout and stderr. No false positives **(Recommended)**
B) Before the run: scan the code for `import numpy`-style lines and refuse without running (faster to fail, but a string or comment that mentions numpy is a false positive)
C) Both: pre-scan as a hint, and post-run is authoritative
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — How code reaches the interpreter
A) **Write it to a read-only `/code/main.py` (or `main.mjs`) mount.** Tracebacks show `File "/code/main.py", line N`, there are no argv size limits, and the guest can't modify it **(Recommended)**
B) Pass it as `-c` / `-e` argv (tracebacks say `<string>` / `<cmdline>`)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — JavaScript flavour
A) **Always an ES module** (`qjs -m`). Top-level `await`, `import * as std from 'qjs:std'` / `'qjs:os'` available, strict mode. Plain scripts that don't rely on sloppy mode work unchanged **(Recommended)**
B) Classic script with `std`/`os` as globals (`--std`)
C) Auto-detect: module if the code contains `import`/`export` at line start, otherwise a script
D) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Default CPU budget semantics
The policy default is `fuel = 2G` and `wall_clock = 5s`. Fuel counts wasm instructions, so it's deterministic but not seconds.
A) Keep both. Report `fuel_used` in every result and publish a calibration table (fuel per typical workload) in the docs, so operators can tune **(Recommended)**
B) Make fuel optional (wall clock only); fuel would be off unless a policy sets it
C) Other (please describe after [Answer]: tag below)

[Answer]: 
