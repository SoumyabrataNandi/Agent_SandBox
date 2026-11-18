# U3 VFS — Functional, NFR & Infrastructure Design

**Inputs:** ADR-001 (GO, trait-wrapper variant), the spike report, U1 `Policy`, U2 `AuditSink`/`EventKind::FsAccess`.
**Crate:** `sandboxd-vfs`. It depends on `sandboxd-policy`, `sandboxd-audit`, `sandboxd-assets`, `wasmtime-wasi` (p1) and `wiggle`.

## 1. Guest filesystem layout (per run)

| Guest path | Backing (host) | Mode | Notes |
|---|---|---|---|
| `/` | `<work>/empty-root/` (shared, empty) | ro | **Catch-all** (spike finding 1): every absolute path outside the mounts lands here, so the interposer audits and denies it |
| `/usr/local/lib/python3.15` | `<cache>/stdlib/<sha>/lib/python3.15` | ro | Python runs only; extracted once from the embedded zip and hash-verified |
| `policy.filesystem.inputs` (`/in`) | `<work>/runs/<run_id>/in/` | ro | Request files materialized here |
| `policy.filesystem.outputs` (`/out`) | `<work>/runs/<run_id>/out/` | rw | Live quota (Q4); collected as artifacts |
| each `policy.filesystem.mount` | operator host dir | ro/rw | From the policy |
| `/dev/sandbox/*` | none (virtual fds) | — | ADR-002 seam; no devices registered in this cycle |

`<run_id>/` is deleted when `RunFs` drops, even if the run panicked or was cancelled.

## 2. Components

```rust
pub struct VfsConfig { pub work_dir: PathBuf, pub cache_dir: PathBuf }   // from server config (U5)

pub struct StdlibCache;      // ensure(&cache_dir, &PYTHON asset) -> PathBuf; atomic extract + marker file with sha
pub struct RunFs;            // create(&VfsConfig, &Policy, RunId, Vec<InputFile>, Language, Arc<dyn AuditSink>) -> Result<RunFs, VfsError>
impl RunFs {
    pub fn wasi(&self, builder: &mut WasiCtxBuilder) -> Result<()>;  // adds preopens in a fixed order
    pub fn interposer(&self, inner: WasiP1Ctx) -> Interposer;          // wraps the built ctx
    pub fn collect_artifacts(&self) -> Result<Collected, VfsError>;  // after the run
}
pub struct InputFile { pub name: String, pub bytes: Vec<u8> }

pub struct Interposer {      // implements WasiSnapshotPreview1 (48 methods; 13 intercepted)
    inner: WasiP1Ctx, mounts: MountTable, fds: FdMap, quota: OutQuota, vfds: VirtualFdTable,
    audit: Arc<dyn AuditSink>, run_id: RunId, policy: String,
}
pub struct VirtualFdTable;   // reserved range ≥ 0x4000_0000; register(path, Box<dyn VirtualDevice>); empty this cycle
pub trait VirtualDevice: Send { async fn read(..); async fn write(..); async fn close(..); }
pub struct Collected { pub artifacts: Vec<Artifact>, pub limit_hit: Option<LimitKind>, pub skipped: Vec<(String, String)> }
pub struct Artifact { pub name: String /* relative to /out, '/'-separated */, pub bytes: Vec<u8>, pub sha256: String }
```

## 3. Interposer rules

| ID | Rule |
|---|---|
| V1 | **Resolve lexically** against the fd's mount: `..` above the mount root → `ENOTCAPABLE` + `fs.access deny "escapes mount"`. This happens *before* wasmtime is called. |
| V2 | *(refined in code; see code-summary delta 1)* Interpreter start-up probes outside the mounts are denied but summarized. **Catch-all root:** any access whose resolved path's mount is `/` → `ENOENT` + `fs.access deny "outside mounts"`, except `stat`/`readdir` of `/` itself, which are allowed so `os.listdir("/")` works and shows the mount points' parent names via wasi-libc. |
| V3 | **Audit after delegation** (spike finding 2). Allowed calls are delegated, then **one** `fs.access` event records the *final* decision. If wasmtime returns `EPERM`/`EACCES`/`ENOTCAPABLE`/`EROFS`, the event says `deny` with that errno as the reason. |
| V4 | Each event includes `op` (open/stat/mkdir/…), the normalized guest path, and `mode` for opens (`r`, `w`, `rw`, `+create`, `+trunc`). |
| V5 | **Stdlib noise control:** reads under the stdlib mount are *not* audited individually (about 200 per Python start). They're counted and summarized as one `fs.access` event, `op=open path=<stdlib> reason="N reads (summary)"`, at run end. Denials there are always audited. |
| V6 | **fd map:** preopens are seeded from the known order; `path_open` adds entries; `fd_close` removes; `fd_renumber` moves. Untracked fds pass through. |
| V7 | **Live `/out` quota** (Q4): `fd_write`/`fd_pwrite`/`fd_filestat_set_size`/`fd_allocate` on fds under `/out` are counted against `limits.artifact_bytes`. Creating a file under `/out` counts against `artifact_count`. Exceeding either → `ENOSPC` (guest sees `OSError: No space left`), `limit.hit kind=artifacts`, and the run is marked `limits_hit=[artifacts]`. |
| V8 | The **same quota idea** applies to rw operator mounts: they're bounded only by the host, which is documented. A per-mount quota is a later option and not in scope. |
| V9 | Virtual fd range: if the guest presents an fd ≥ `0x4000_0000`, it's routed to `VirtualFdTable` (empty → `EBADF`). A `path_open` under `/dev/sandbox` is resolved against registered devices (none → `ENOENT`). |

## 4. Inputs and artifacts

| ID | Rule |
|---|---|
| I1 | Input names (Q3): `[A-Za-z0-9._-]{1,128}` plus optional `/` subdirectories (max depth 4), with no `..`, empty components, leading `/`, or Windows-reserved names (`CON`, `NUL`, `COM1`…). Duplicates → error. The total is checked against `limits.input_bytes` *before* anything is written. |
| I2 | Inputs are written with exclusive-create into `in/` and then exposed read-only. |
| A1 | Collection walks `out/` in sorted order. Symlinks and special files are **skipped and reported** in `skipped`, never followed (Q5). |
| A2 | Caps are re-checked at collection (count and bytes), as defence in depth behind V7. On overflow, collect up to the cap and set `limit_hit=artifacts`. |
| A3 | Artifact names are `/`-separated paths relative to `/out` (the same on every OS), each with a sha256. Bytes are returned in memory (Q2). |

## 5. Stdlib cache (ADR-004)
`<cache>/stdlib/<zip-sha256>/` is extracted into a sibling temp dir and then renamed atomically. A `.complete` marker holds the sha. If the marker is present and matches, extraction is skipped. Concurrent first runs race safely (rename loser cleans up). A corrupted cache, detected by the marker missing or not matching, is deleted and extracted again. The zip comes only from the embedded, build-verified asset.

## 6. NFR (scaled)
- **Security:** no `unsafe`; all guest memory access goes through wiggle's checked API. The interposer only adds restrictions; wasmtime-wasi/cap-std remain the primary enforcement. Run dirs are created with 0700 (Unix).
- **Performance:** a per-call cost of one `HashMap` lookup plus lexical normalization. Stdlib reads skip event creation (V5). The spike measured no detectable overhead.
- **Windows:** host paths go through `cap-std` (handles `\\?\`). Guest paths are always `/`-separated. Run-dir deletion retries briefly to cope with Windows file locks.
- **Testing:** unit tests for `resolve`, input-name validation, quota math and the cache marker. Integration tests run **real CPython** through `RunFs` + `Interposer` + a minimal wasmtime harness (dev-dependency), covering the trial cases plus: catch-all `/etc/passwd` audited, write-to-ro audited as deny (V3), `/out` quota → ENOSPC, artifact collection, symlink skipped (Unix CI), and run dir removed on drop.

## 7. Infrastructure
None. The new workspace dependencies are `wasmtime`/`wasmtime-wasi`/`wiggle` 50.0.2 and `zip` 2 (deflate only). `spikes/adr001` is removed from the workspace once U3 lands; it stays in git history.
