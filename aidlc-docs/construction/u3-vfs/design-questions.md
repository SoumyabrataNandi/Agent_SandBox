# U3 VFS — Design Questions

Design: `design.md`. Answer after each `[Answer]:` tag, or reply **"accept recommended defaults"**.

### Question 1 — Catch-all `/` preopen (spike finding 1)
A) Yes: an empty, read-only `/`, so out-of-mount attempts like `/etc/passwd` reach the interposer and get audited as `deny "outside mounts"` **(Recommended; needed for "every capability use is audited")**
B) No: keep the gap and document that out-of-mount attempts aren't audited
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 2 — Artifact delivery from VFS
A) In memory. `collect_artifacts` returns bytes, bounded by `limits.artifact_bytes`, which is at most 1 GiB per policy (16 MiB by default). U5 decides inline vs. download **(Recommended for this cycle)**
B) Move files into an artifact store directory with a TTL and return references (better for large outputs; adds cleanup machinery)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 3 — Input file names
A) Relative paths allowed (`data/2025/sales.csv`, depth ≤ 4), strictly validated **(Recommended; agents often send a small tree)**
B) Flat names only (`sales.csv`)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 4 — `/out` size enforcement
Without a live check, a guest can fill the host disk during a run (`while True: f.write(...)`), and the cap would only be checked afterwards.
A) **Live quota in the interposer.** Count bytes written and files created under `/out`; return `ENOSPC` past `artifact_bytes` / `artifact_count` **(Recommended)**
B) Post-run check only (disk-fill risk, but simpler)
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 5 — Symlinks or special files found in `/out` at collection
A) Skip them, list them as `skipped` in the result, and audit them; never follow them **(Recommended)**
B) Fail the whole run's artifact collection
C) Other (please describe after [Answer]: tag below)

[Answer]: 

### Question 6 — Default host locations (overridable in config in U5)
A) Cache under the OS cache dir (`%LOCALAPPDATA%\sandboxd\cache`, `~/.cache/sandboxd`, `~/Library/Caches/sandboxd`). Per-run work dirs under `<cache>/../work` on the same volume **(Recommended)**
B) Everything under the OS temp dir (simpler, but can be wiped by the OS while the server runs)
C) Other (please describe after [Answer]: tag below)

[Answer]: 
