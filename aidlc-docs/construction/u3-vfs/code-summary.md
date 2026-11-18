# U3 VFS — Code Summary & Test Results (2026-11-18)

Design answers Q1–Q6: all recommended (catch-all `/`, in-memory artifacts, relative input paths, live `/out` quota, skip symlinks, OS cache dir).

| File | Content |
|---|---|
| `src/interposer.rs` | `Interposer`: `WasiSnapshotPreview1` over `WasiP1Ctx`. 48 methods, 17 intercepted (10 path ops, fd_close/renumber, fd_write/pwrite/filestat_set_size/allocate for quota, fd_read/fdstat_get/seek for virtual fds). Rules V1–V9; one audit event per op with the final errno; stdlib reads and start-up probes summarized |
| `src/runfs.rs` | `RunFs`: input validation before disk (names, case-insensitive duplicates, file/dir clash, `input_bytes`); layout + preopens in fd order; artifact collection (sorted, no symlink following, caps); cleanup on drop with Windows retry; `quiet_probes` derivation |
| `src/paths.rs` | `resolve` (lexical, mount-floor aware) and `validate_input_name` (incl. Windows reserved names) |
| `src/stdlib.rs` | `ensure_stdlib`: atomic, marker-verified extraction of `lib/**` from the embedded zip; repair on corruption; race-safe |
| `src/vfd.rs` | `VirtualFdTable`, `VirtualDevice` (boxed-future, object-safe), `VFD_BASE = 0x4000_0000` |
| `src/config.rs` | `VfsConfig::default_locations()` per OS; `under(root)` |
| `tests/cpython.rs` | Real CPython 3.15 end-to-end (6 tests; symlink test is Unix-only) |

**Tests:** 10 (4 unit + 6 CPython integration). Workspace total: 48. fmt and clippy `-D warnings` are clean.

| Verified with real CPython | |
|---|---|
| csv from `/in/data/…`, read ro mount, `pathlib.rglob`, makedirs/rename in `/out`, `os.listdir("/") == []` | ✅ |
| Artifacts sorted, `/`-separated, sha256 correct; run dir deleted on drop | ✅ |
| `/etc/passwd`, `/evil.txt` → deny "outside mounts"; `/data/../outside.txt` → deny "escapes mount"; host secret never read | ✅ |
| Write to ro mount / `/in` → **final** outcome audited as deny (V3) | ✅ |
| `/out` byte quota → `ENOSPC` live, `limit.hit artifacts`; file-count quota → 4th create fails, rewriting an existing file is fine | ✅ |
| `/dev/sandbox/echo` test device: open/write/read/close through the ADR-002 seam | ✅ |
| Clean run: **zero individual denials**; 1 stdlib summary + 1 start-up-probe summary event | ✅ |

## Design deltas found during implementation
1. **CPython start-up probes (refines V2).** With the catch-all `/`, CPython's `getpath` probes (`/pyvenv.cfg`, `/pybuilddir.txt`, `…/python315.zip`, `/lib/python3.15/os.py[c]`, and the mount ancestors `/usr`, `/usr/local`, `/usr/local/lib`) reach the host: 12 per run. They stay **denied** (ENOENT, same as before) but are counted and emitted as one summary event. The list comes from the mount set, so nothing broader is quieted. Writes are never quiet.
2. **`-I` ignores `PYTHONDONTWRITEBYTECODE`.** Isolated mode drops all `PYTHON*` env vars, so CPython tried to create `__pycache__` in the read-only stdlib (27 audited denials). **U4 must launch with `-I -B -S`**, and must not rely on `PYTHONHOME`. The default prefix `/usr/local` already matches the mount.
3. Hard links *into* `/out` are refused with EPERM. Otherwise artifact collection could read a file linked in from a ro mount and bypass collection semantics.
4. `/out` quota counts bytes written, not the final size: conservative (rewrites count twice). This is documented and fine at the default 16 MiB.

`spikes/adr001` has been removed from the tree (it remains in git history, commit d230f3a).
