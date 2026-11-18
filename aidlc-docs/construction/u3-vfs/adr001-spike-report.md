# ADR-001 Spike Report: WASI p1 filesystem interposer

**Date:** 2026-11-18 · **Code:** `spikes/adr001/` (throwaway) · **Stack:** wasmtime 50.0.2, wasmtime-wasi 50.0.2 (p1), CPython 3.15.2 WASI, Windows 11 release build
**Recommendation: GO.** Every exit criterion is met with an approach that is simpler and safer than the one in the ADR.

## Approach that worked: "trait wrapper" (better than the ADR's two-layer linker)
wasmtime-wasi generates its preview1 layer with `wiggle::from_witx!`, and the generated items are public:
- `p1::wasi_snapshot_preview1::WasiSnapshotPreview1`: a trait with 48 methods, using native `async fn`
- `p1::wasi_snapshot_preview1::add_to_linker<T, U: WasiSnapshotPreview1>`, which is **generic over the implementation**
- `p1::types` (Fd, Errno, Rights, …)

So `Interposer { inner: WasiP1Ctx, … }` implements the trait. It delegates 37 methods unchanged and intercepts 11:
- the path calls: `path_open`, `path_filestat_get`, `path_filestat_set_times`, `path_create_directory`, `path_remove_directory`, `path_unlink_file`, `path_rename`, `path_link`, `path_symlink` and `path_readlink`;
- the fd lifecycle calls `fd_close` and `fd_renumber`, which keep the fd→path map up to date.

The wrapper then calls `add_to_linker(&mut linker, |s| s)`.
- **No `Func` re-wrapping and no `Caller` tricks**, which is why the reported `func_wrap` breakage doesn't apply.
- **No `unsafe`.** Guest strings are read through wiggle's checked `GuestMemory::as_cow_str`.
- **Defence in depth is preserved.** Allowed calls go to wasmtime-wasi's own cap-std preopen enforcement.

## Results
| Criterion | Result |
|---|---|
| `open()`, `os.listdir()`, `pathlib.rglob()`, `csv`, `makedirs`, `rename` under `/out`, stdlib listing | ✅ all work; 226 calls intercepted in one run |
| Denied path → audit event | ✅ `DENY open /data/secret/key.txt (policy deny)`, including via `sub/../secret`; `DENY open "../outside.txt" (escapes mount /data)` before wasmtime is called |
| Overhead < 5% (median of 7, stdlib-import benchmark) | ✅ OFF 842 ms / ON 804 ms, −4.6%: within noise, no measurable cost |
| Host sees `/out` writes | ✅ `/out/a/result.json` present on host after rename |
| Write to ro mount | ✅ refused by wasmtime (`Operation not permitted`), as defence in depth |

## Findings that change the U3/U4 design
1. **Opens outside every mount never reach the host.** `open("/etc/passwd")` fails *inside* wasi-libc (ENOENT) because no preopen matches, so there is nothing to audit. **Fix for U3:** preopen an empty, read-only host dir at `/` as a catch-all. wasi-libc picks the longest-prefix preopen, so every other absolute path lands on that fd, and the interposer audits and denies it. This needs a check in U3 that `os.listdir("/")` stays sane.
2. **Audit after delegation, not before.** The spike logged `ALLOW open /data/new.txt` for a write that wasmtime then refused. The real interposer must log the *final* outcome, including the open mode and the errno when wasmtime denies.
3. **`fd_renumber` and `fd_close` must update the fd map**, as the spike does, or audit paths go stale. Fds the interposer didn't see opened (stdio) pass through untracked.
4. **Errno text quirk.** wasi-libc renders WASI `EACCES` as `[Errno 2] Permission denied`. Cosmetic; worth documenting for users.
5. **Directory listings still show the names of policy-denied entries** (the spike's `deny_prefixes`). This doesn't matter for production, which has no sub-mount deny rules: mounts are whole directories, and denials are escapes and out-of-mount paths.

## Risks surfaced for U4 (not U3)
- **The CPython cold start misses NFR-3.** One functional run took 527 ms; the import benchmark took about 800 ms. The target is ≤ 300 ms. With no snapshots, CPython initialization dominates. Options: (a) accept and re-baseline NFR-3 for this cycle; (b) pull wizer pre-initialization forward from Phase 5; (c) trim startup (`-S`, `-I`, frozen modules). I'll measure `print(1)` precisely in U4 and bring numbers.
- **First AOT compile of `python.wasm` takes 9.0 s.** That confirms the need for `ModuleCache` (serialize the `.cwasm` once and verify its hash, per ADR-004). Later runs only deserialize.
- `Config::async_support` is deprecated and a no-op in wasmtime 50, since async is always available. Update ADR-003 wording.

## Not covered by the spike (planned for U3/U6)
- Host symlink pointing outside a mount. Creating symlinks on Windows needs Developer Mode, so this is tested in CI on Linux/macOS. cap-std is expected to block it.
- Windows host paths with spaces and Unicode, and very long paths.
