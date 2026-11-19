# C3-U3 Snapshot Integration — Design Questions

Answer each by putting a letter after `[Answer]:`. Option **A** is the recommendation in every case. "accept recommended defaults" = all A.

## Q1 How the custom interpreters ship
A) **Embedded in the binary as required, pinned assets** (like today's interpreters): about +9.5 MB binary size, single-binary deployment kept, verified at fetch and at build. **(Recommended)**
B) Downloaded at runtime into the cache (smaller binary, but needs network access at first start)

[Answer]: A

## Q2 Audit visibility of the interpreter path
A) **`run.start` gains `interpreter: "snapshot" | "upstream"`** (additive field), so operators can see when a policy falls back. **(Recommended)**
B) Logs only

[Answer]: A

## Q3 Snapshots on platforms without copy-on-write memory images (if Windows/macOS turn out to copy on each instantiation)
A) **Still use snapshots there:** a restored run is still much faster than a full CPython start-up. Document the per-OS numbers. **(Recommended)**
B) Linux only

[Answer]: A

## Q4 The spike's `sandboxd-step` diagnostic export
A) **Compiled out of release builds** (kept behind `-DSANDBOXD_SPIKE` for the spike job). **(Recommended: smallest surface)**
B) Keep it in releases

[Answer]: A

## Q5 When the interpreter release is published
A) **Automatically** by `interpreters.yml` on `main`, when interpreter sources change and the spike job's `go` is true. I then pin it in `assets/manifest.toml` in a follow-up commit. **(Recommended)**
B) Only on a manual `workflow_dispatch`

[Answer]: A
