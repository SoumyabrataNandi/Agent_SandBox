# Cycle 3 Application Design — Questions

Answer each by putting a letter after `[Answer]:`. Option **A** is the recommendation in every case. "accept recommended defaults" = all A.

## Q1 CPython string-hash secret on snapshot runs
Requirement S1.5 asked for per-run re-seeding. CPython fixes its hash secret during initialisation, which is exactly what the snapshot captures, so that can't be done.
A) **A random secret generated when each host builds its snapshot.** Different installs and rebuilds differ; runs on one host share it. `random` is still re-seeded per run. This amends S1.5. **(Recommended: set/dict order stays unpredictable across hosts; runs can't learn anything about each other from it)**
B) A fixed seed (`PYTHONHASHSEED=0`): fully reproducible snapshots, but predictable hash order everywhere
C) Other (please describe after [Answer]: tag below)

[Answer]: A

## Q2 How the snapshot path runs `/code/main.py`
A) **Natively from C** (`PyRun_SimpleFileExFlags`) in the `sandboxd-run` export. CPython prints tracebacks and handles `SystemExit` itself, with no Python-level `compile()`. The network patches are applied once in the snapshot. **(Recommended: fastest, and tracebacks are exactly CPython's)**
B) Reuse the C2-U3 Python bootstrap (`sandboxd_boot.main()`) inside the snapshot
C) Other (please describe after [Answer]: tag below)

[Answer]: A

## Q3 Python preload list (modules already imported in the snapshot)
A) **Curated:** `json re collections datetime csv math statistics decimal fractions functools itertools operator string textwrap typing dataclasses enum base64 hashlib random struct io pathlib`, plus the network stack (`socket http.client urllib.request urllib.parse email.message`) already patched. **(Recommended: covers typical agent code; still a modest snapshot)**
B) Minimal: interpreter start-up only, no extra imports
C) Large: most of the pure-Python stdlib (bigger snapshot and memory floor)

[Answer]: A

## Q4 Session cell file names (requirement SE1.2 said `File "<cell N>"`)
A) **Real files `/code/cell_<N>.py` / `.mjs`**, written by the host, so tracebacks include the source lines. Amends SE1.2. **(Recommended: tracebacks are actually useful)**
B) Pseudo file names `<cell N>`, so tracebacks have no source lines

[Answer]: A

## Q5 `sys.exit(n)` / uncaught `SystemExit` inside a session cell
A) **Ends that call** with exit code n (outcome `exit` when n ≠ 0); **the session continues**, like a notebook kernel. **(Recommended)**
B) Ends the session

[Answer]: A

## Q6 How CI results reach this session (no `gh` CLI here)
A) **Workflows push result JSON to an orphan `ci-results` branch;** I fetch it with git. **(Recommended: no manual copying)**
B) You copy job summaries or screenshots to me

[Answer]: A

## Q7 A policy's memory limit is below the snapshot's memory floor
A) **Those runs automatically use the upstream (non-snapshot) interpreter path,** logged once per policy at start-up and noted in `policy check`. **(Recommended: never fails, just slower)**
B) Refuse such runs, with an error telling the operator to raise the limit

[Answer]: A

## Q8 JavaScript session cells
A) **Each cell runs as a global script with top-level `await`** (`std.evalScript(…, {async: true})`). `var`/`let`/`const`/function/class declarations persist across cells. `import` statements are not allowed in cells; use `await import(…)`. **(Recommended: notebook-like behaviour)**
B) Each cell is a module; only `globalThis` assignments persist

[Answer]: A
