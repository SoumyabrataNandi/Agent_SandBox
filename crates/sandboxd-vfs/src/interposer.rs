//! WASI p1 interposer (ADR-001, trait-wrapper variant; U3 design §3, rules V1–V9).
//!
//! Wraps wasmtime-wasi's `WasiP1Ctx` and implements `WasiSnapshotPreview1` by delegation.
//! Path-taking calls are resolved lexically against the fd's mount, checked, delegated, and
//! audited with their *final* outcome. wasmtime-wasi's cap-std preopens remain the primary
//! enforcement; this layer can only add denials.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use sandboxd_audit::{AuditEvent, AuditSink, Decision, EventKind, FsOp, LimitKind, RunId};
use wasmtime_wasi::p1::{
    WasiP1Ctx,
    types::{self, Errno},
    wasi_snapshot_preview1::WasiSnapshotPreview1,
};
use wiggle::{GuestMemory, GuestPtr};

use crate::{
    paths::{resolve, within},
    vfd::VirtualFdTable,
};

/// What a preopened guest directory is for. Drives rules V2, V5, V7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    /// The empty `/` catch-all: only `/` itself may be listed.
    CatchAll,
    /// The CPython stdlib: reads are summarized, not logged one by one.
    Stdlib,
    /// Request inputs (read-only).
    Inputs,
    /// `/out`: subject to the live artifact quota.
    Outputs,
    /// Operator mount from the policy.
    Policy,
    /// The submitted program (`/code`, read-only).
    Code,
    /// Session-private writable directory (`/work`, cycle 3 C3-U4): live quota like `/out`, but
    /// not collected.
    Work,
    /// sandboxd guest helpers (`/usr/local/lib/sandboxd`, read-only): reads are summarized.
    Helpers,
}

/// One preopened directory, in preopen (fd) order.
#[derive(Debug, Clone)]
pub struct MountInfo {
    pub guest: String,
    pub host: PathBuf,
    pub kind: MountKind,
}

#[derive(Debug, Clone)]
struct FdEntry {
    mount: usize,
    path: String,
}

/// Live `/out` quota (rule V7). Counts bytes actually written, not final sizes (conservative).
#[derive(Debug, Clone, Copy)]
pub struct OutQuota {
    pub max_bytes: u64,
    pub max_files: u32,
    pub bytes: u64,
    pub files: u32,
    pub hit: bool,
}

/// Shared handle to the live quota, so a session can start each call with a fresh one (C3-U4)
/// while the guest (and with it the interposer) keeps running.
#[derive(Debug, Clone)]
pub struct QuotaHandle(Arc<std::sync::Mutex<OutQuota>>);

impl QuotaHandle {
    pub(crate) fn new(q: OutQuota) -> Self {
        Self(Arc::new(std::sync::Mutex::new(q)))
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, OutQuota> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Current counters.
    pub fn get(&self) -> OutQuota {
        *self.lock()
    }
    /// Zero the counters (limits unchanged).
    pub fn reset(&self) {
        self.reset_to(0, 0);
    }
    /// Start counting from `bytes`/`files` already stored (a session's `/work`), limits unchanged.
    pub fn reset_to(&self, bytes: u64, files: u32) {
        let mut q = self.lock();
        q.bytes = bytes;
        q.files = files;
        q.hit = false;
    }
}

/// The run (and session) id stamped on audit events. Sessions (C3-U4) switch it per call.
#[derive(Debug, Clone)]
pub struct CallIds(Arc<std::sync::Mutex<(RunId, Option<String>)>>);

impl CallIds {
    /// Ids for a one-shot run.
    pub fn new(run_id: RunId) -> Self {
        Self(Arc::new(std::sync::Mutex::new((run_id, None))))
    }
    /// Attribute what follows to `run_id` (and `session_id`).
    pub fn set(&self, run_id: RunId, session_id: Option<String>) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = (run_id, session_id);
    }
    /// The current run id.
    pub fn run_id(&self) -> RunId {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).0
    }
    /// Add the current ids to `ev`.
    pub fn stamp(&self, ev: AuditEvent) -> AuditEvent {
        let g = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let ev = ev.run(g.0);
        match &g.1 {
            Some(s) => ev.session(s.clone()),
            None => ev,
        }
    }
}

/// What the interposer observed, for the runtime's result and `run.end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterposerReport {
    pub limit_hit: Option<LimitKind>,
    pub stdlib_reads: u64,
    /// Interpreter start-up probes outside the mounts (denied; summarized in one event).
    pub quiet_denials: u64,
    pub out_bytes_written: u64,
    pub out_files_created: u32,
}

/// The wrapper installed in the wasmtime `Store`.
pub struct Interposer {
    inner: WasiP1Ctx,
    mounts: Vec<MountInfo>,
    fds: HashMap<u32, FdEntry>,
    quota: QuotaHandle,
    vfds: VirtualFdTable,
    audit: Arc<dyn AuditSink>,
    ids: CallIds,
    policy: String,
    stdlib_reads: u64,
    helper_reads: u64,
    /// Known interpreter start-up probes outside every mount (denied, summarized).
    quiet_probes: Vec<String>,
    quiet_denials: u64,
}

impl std::fmt::Debug for Interposer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interposer")
            .field("mounts", &self.mounts)
            .field("tracked_fds", &self.fds.len())
            .field("quota", &self.quota.get())
            .finish_non_exhaustive()
    }
}

/// First fd wasmtime-wasi assigns to preopens (0–2 are stdio).
pub const FIRST_PREOPEN_FD: u32 = 3;

/// Context the interposer needs besides the inner ctx.
pub(crate) struct InterposerParts {
    pub quiet_probes: Vec<String>,
    pub mounts: Vec<MountInfo>,
    pub quota: QuotaHandle,
    pub vfds: VirtualFdTable,
    pub audit: Arc<dyn AuditSink>,
    pub ids: CallIds,
    pub policy: String,
}

/// Result of the pre-delegation check for one path argument.
struct Checked {
    mount: usize,
    path: String,
    /// Path under `/dev/sandbox` (only `path_open` may proceed with it).
    device: bool,
}

fn errno_of(e: &types::Error) -> Option<Errno> {
    e.downcast_ref().copied()
}

fn errno_name(e: Errno) -> String {
    format!("{e:?}").to_ascii_lowercase()
}

fn is_denial(e: Errno) -> bool {
    matches!(
        e,
        Errno::Acces | Errno::Perm | Errno::Notcapable | Errno::Rofs
    )
}

/// `r`, `w`, `rw` plus `+create`, `+trunc`, `+excl`, `+append`, `+dir`.
fn open_mode(of: types::Oflags, rb: types::Rights, ff: types::Fdflags) -> String {
    let r = rb.contains(types::Rights::FD_READ);
    let w = rb.contains(types::Rights::FD_WRITE);
    let mut s = match (r, w) {
        (true, true) => "rw",
        (false, true) => "w",
        _ => "r",
    }
    .to_string();
    for (flag, name) in [
        (of.contains(types::Oflags::CREAT), "+create"),
        (of.contains(types::Oflags::TRUNC), "+trunc"),
        (of.contains(types::Oflags::EXCL), "+excl"),
        (of.contains(types::Oflags::DIRECTORY), "+dir"),
        (ff.contains(types::Fdflags::APPEND), "+append"),
    ] {
        if flag {
            s.push_str(name);
        }
    }
    s
}

impl Interposer {
    /// Wrap `inner`. `parts.mounts` must be in the same order the preopens were added.
    pub(crate) fn new(inner: WasiP1Ctx, parts: InterposerParts) -> Self {
        let fds = parts
            .mounts
            .iter()
            .enumerate()
            .map(|(i, m)| {
                (
                    FIRST_PREOPEN_FD + i as u32,
                    FdEntry {
                        mount: i,
                        path: m.guest.clone(),
                    },
                )
            })
            .collect();
        Self {
            inner,
            mounts: parts.mounts,
            fds,
            quota: parts.quota,
            vfds: parts.vfds,
            audit: parts.audit,
            ids: parts.ids,
            policy: parts.policy,
            stdlib_reads: 0,
            helper_reads: 0,
            quiet_probes: parts.quiet_probes,
            quiet_denials: 0,
        }
    }

    /// Emit the stdlib summary event (V5) and report what happened. Call once after the run.
    pub fn finish(&mut self) -> InterposerReport {
        if self.stdlib_reads > 0
            && let Some(m) = self.mounts.iter().find(|m| m.kind == MountKind::Stdlib)
        {
            let path = m.guest.clone();
            let n = self.stdlib_reads;
            self.emit(
                FsOp::Open,
                path,
                None,
                Decision::Allow,
                Some(format!("{n} reads (summary)")),
            );
        }
        if self.helper_reads > 0
            && let Some(m) = self.mounts.iter().find(|m| m.kind == MountKind::Helpers)
        {
            let path = m.guest.clone();
            let n = std::mem::take(&mut self.helper_reads);
            self.emit(
                FsOp::Open,
                path,
                None,
                Decision::Allow,
                Some(format!("{n} reads (summary)")),
            );
        }
        if self.quiet_denials > 0 {
            let n = self.quiet_denials;
            self.emit(
                FsOp::Stat,
                "/".into(),
                None,
                Decision::Deny,
                Some(format!(
                    "{n} interpreter start-up probes outside mounts (summary)"
                )),
            );
        }
        InterposerReport {
            limit_hit: self.quota.get().hit.then_some(LimitKind::Artifacts),
            stdlib_reads: std::mem::take(&mut self.stdlib_reads),
            quiet_denials: std::mem::take(&mut self.quiet_denials),
            out_bytes_written: self.quota.get().bytes,
            out_files_created: self.quota.get().files,
        }
    }

    /// The live quota, shared (sessions reset it per call).
    pub fn quota_handle(&self) -> QuotaHandle {
        self.quota.clone()
    }

    /// The wrapped wasmtime-wasi context.
    pub fn inner_mut(&mut self) -> &mut WasiP1Ctx {
        &mut self.inner
    }

    fn emit(
        &self,
        op: FsOp,
        path: String,
        mode: Option<String>,
        decision: Decision,
        reason: Option<String>,
    ) {
        self.audit.emit(
            self.ids
                .stamp(AuditEvent::new(EventKind::FsAccess {
                    op,
                    path,
                    mode,
                    decision,
                    reason,
                }))
                .policy(self.policy.clone()),
        );
    }

    /// V1/V2/V9 pre-checks. `Ok(None)` → untracked dirfd, pass through untouched.
    fn check(
        &mut self,
        op: FsOp,
        memory: &GuestMemory<'_>,
        dirfd: types::Fd,
        path: GuestPtr<str>,
        mode: Option<&str>,
    ) -> Result<Option<Checked>, types::Error> {
        let rel = memory.as_cow_str(path)?.into_owned();
        let Some(entry) = self.fds.get(&u32::from(dirfd)).cloned() else {
            return Ok(None);
        };
        let mount = &self.mounts[entry.mount];
        let full = match resolve(&mount.guest, &entry.path, &rel) {
            Ok(p) => p,
            Err(why) => {
                let shown = format!("{}/{rel}", entry.path.trim_end_matches('/'));
                self.emit(op, shown, mode.map(Into::into), Decision::Deny, Some(why));
                return Err(Errno::Notcapable.into());
            }
        };
        if mount.kind == MountKind::CatchAll {
            // V9: device paths are only meaningful to path_open.
            if within(&full, sandboxd_policy::DEVICE_GUEST_PATH) {
                if op == FsOp::Open {
                    return Ok(Some(Checked {
                        mount: entry.mount,
                        path: full,
                        device: true,
                    }));
                }
                self.emit(
                    op,
                    full,
                    mode.map(Into::into),
                    Decision::Deny,
                    Some("not supported on devices".into()),
                );
                return Err(Errno::Noent.into());
            }
            // V2: only `/` itself may be inspected; everything else is outside every mount.
            let read_only_view = matches!(op, FsOp::Stat)
                || mode.is_some_and(|m| m.starts_with('r') && !m.contains("+create"));
            if !(full == "/" && read_only_view) {
                let readish = matches!(op, FsOp::Stat)
                    || mode.is_some_and(|m| m.starts_with('r') && !m.contains('+'));
                if readish && self.quiet_probes.contains(&full) {
                    self.quiet_denials += 1;
                    return Err(Errno::Noent.into());
                }
                self.emit(
                    op,
                    full,
                    mode.map(Into::into),
                    Decision::Deny,
                    Some("outside mounts".into()),
                );
                return Err(Errno::Noent.into());
            }
        }
        Ok(Some(Checked {
            mount: entry.mount,
            path: full,
            device: false,
        }))
    }

    /// V3/V5: one event with the final outcome.
    fn record<T>(
        &mut self,
        op: FsOp,
        c: &Option<Checked>,
        mode: Option<String>,
        r: &Result<T, types::Error>,
    ) {
        let Some(c) = c else { return };
        let errno = r.as_ref().err().and_then(errno_of);
        let decision = if errno.is_some_and(is_denial) {
            Decision::Deny
        } else {
            Decision::Allow
        };
        if decision == Decision::Allow {
            match self.mounts[c.mount].kind {
                MountKind::Stdlib => {
                    self.stdlib_reads += 1;
                    return;
                }
                MountKind::Helpers => {
                    self.helper_reads += 1;
                    return;
                }
                _ => {}
            }
        }
        let reason = errno.map(errno_name);
        self.emit(op, c.path.clone(), mode, decision, reason);
    }

    fn is_out_fd(&self, fd: types::Fd) -> bool {
        self.fds.get(&u32::from(fd)).is_some_and(|e| {
            matches!(
                self.mounts[e.mount].kind,
                MountKind::Outputs | MountKind::Work
            )
        })
    }

    /// V7: reserve `n` more bytes under `/out`, or fail with ENOSPC.
    fn reserve_out_bytes(&mut self, n: u64) -> Result<(), types::Error> {
        let q = self.quota.get();
        if q.bytes.saturating_add(n) > q.max_bytes {
            self.quota_hit("bytes");
            return Err(Errno::Nospc.into());
        }
        Ok(())
    }

    fn quota_hit(&mut self, what: &str) {
        let q = self.quota.get();
        if !q.hit {
            self.quota.lock().hit = true;
            let (limit, observed) = if what == "files" {
                (u64::from(q.max_files), u64::from(q.files) + 1)
            } else {
                (q.max_bytes, q.bytes)
            };
            self.audit.emit(
                self.ids
                    .stamp(AuditEvent::new(EventKind::LimitHit {
                        kind: LimitKind::Artifacts,
                        limit,
                        observed,
                    }))
                    .policy(self.policy.clone()),
            );
        }
    }

    /// Length of the first non-empty buffer, which is all wasmtime-wasi writes per call.
    fn first_ciovec_len(
        memory: &GuestMemory<'_>,
        ciovs: types::CiovecArray,
    ) -> Result<u64, types::Error> {
        for iov in ciovs.iter() {
            let iov = memory.read(iov?)?;
            if iov.buf_len > 0 {
                return Ok(u64::from(iov.buf_len));
            }
        }
        Ok(0)
    }

    fn host_exists(&self, c: &Checked) -> bool {
        let m = &self.mounts[c.mount];
        let rel = c
            .path
            .strip_prefix(&m.guest)
            .unwrap_or("")
            .trim_start_matches('/');
        m.host.join(rel).symlink_metadata().is_ok()
    }
}

macro_rules! delegate_path_op {
    ($self:ident, $op:expr, $m:ident, $fd:ident, $p:ident, $call:expr) => {{
        let c = $self.check($op, $m, $fd, $p, None)?;
        let r = $call;
        $self.record($op, &c, None, &r);
        r
    }};
}

impl WasiSnapshotPreview1 for Interposer {
    fn set_hostcall_fuel(&mut self, fuel: usize) {
        self.inner.set_hostcall_fuel(fuel)
    }
    fn args_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        a: GuestPtr<GuestPtr<u8>>,
        b: GuestPtr<u8>,
    ) -> Result<(), types::Error> {
        self.inner.args_get(m, a, b)
    }
    fn args_sizes_get(
        &mut self,
        m: &mut GuestMemory<'_>,
    ) -> Result<(types::Size, types::Size), types::Error> {
        self.inner.args_sizes_get(m)
    }
    fn environ_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        a: GuestPtr<GuestPtr<u8>>,
        b: GuestPtr<u8>,
    ) -> Result<(), types::Error> {
        self.inner.environ_get(m, a, b)
    }
    fn environ_sizes_get(
        &mut self,
        m: &mut GuestMemory<'_>,
    ) -> Result<(types::Size, types::Size), types::Error> {
        self.inner.environ_sizes_get(m)
    }
    fn clock_res_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        id: types::Clockid,
    ) -> Result<types::Timestamp, types::Error> {
        self.inner.clock_res_get(m, id)
    }
    fn clock_time_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        id: types::Clockid,
        p: types::Timestamp,
    ) -> Result<types::Timestamp, types::Error> {
        self.inner.clock_time_get(m, id, p)
    }
    async fn fd_advise(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filesize,
        l: types::Filesize,
        a: types::Advice,
    ) -> Result<(), types::Error> {
        self.inner.fd_advise(m, fd, o, l, a).await
    }

    fn fd_allocate(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filesize,
        l: types::Filesize,
    ) -> Result<(), types::Error> {
        if self.is_out_fd(fd) {
            self.reserve_out_bytes(l)?;
        }
        self.inner.fd_allocate(m, fd, o, l)
    }

    async fn fd_close(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        let n = u32::from(fd);
        if VirtualFdTable::is_virtual(n) {
            let mut dev = self.vfds.take(n).ok_or(Errno::Badf)?;
            return dev.close().await.map_err(Into::into);
        }
        let r = self.inner.fd_close(m, fd).await;
        if r.is_ok() {
            self.fds.remove(&n);
        }
        r
    }

    async fn fd_datasync(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        self.inner.fd_datasync(m, fd).await
    }

    async fn fd_fdstat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Fdstat, types::Error> {
        if VirtualFdTable::is_virtual(u32::from(fd)) {
            if self.vfds.get(u32::from(fd)).is_none() {
                return Err(Errno::Badf.into());
            }
            return Ok(types::Fdstat {
                fs_filetype: types::Filetype::CharacterDevice,
                fs_flags: types::Fdflags::empty(),
                fs_rights_base: types::Rights::FD_READ | types::Rights::FD_WRITE,
                fs_rights_inheriting: types::Rights::empty(),
            });
        }
        self.inner.fd_fdstat_get(m, fd).await
    }

    fn fd_fdstat_set_flags(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Fdflags,
    ) -> Result<(), types::Error> {
        self.inner.fd_fdstat_set_flags(m, fd, f)
    }
    fn fd_fdstat_set_rights(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        a: types::Rights,
        b: types::Rights,
    ) -> Result<(), types::Error> {
        self.inner.fd_fdstat_set_rights(m, fd, a, b)
    }
    async fn fd_filestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Filestat, types::Error> {
        if VirtualFdTable::is_virtual(u32::from(fd)) {
            // CPython's `open()` fstat()s every fd; devices look like character devices.
            if self.vfds.get(u32::from(fd)).is_none() {
                return Err(Errno::Badf.into());
            }
            return Ok(types::Filestat {
                dev: 0,
                ino: 0,
                filetype: types::Filetype::CharacterDevice,
                nlink: 1,
                size: 0,
                atim: 0,
                mtim: 0,
                ctim: 0,
            });
        }
        self.inner.fd_filestat_get(m, fd).await
    }

    async fn fd_filestat_set_size(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        size: types::Filesize,
    ) -> Result<(), types::Error> {
        if self.is_out_fd(fd) {
            let cur = self.inner.fd_filestat_get(m, fd).await?.size;
            let growth = size.saturating_sub(cur);
            self.reserve_out_bytes(growth)?;
            let r = self.inner.fd_filestat_set_size(m, fd, size).await;
            if r.is_ok() {
                self.quota.lock().bytes += growth;
            }
            return r;
        }
        self.inner.fd_filestat_set_size(m, fd, size).await
    }

    async fn fd_filestat_set_times(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        a: types::Timestamp,
        b: types::Timestamp,
        f: types::Fstflags,
    ) -> Result<(), types::Error> {
        self.inner.fd_filestat_set_times(m, fd, a, b, f).await
    }

    async fn fd_read(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        iovs: types::IovecArray,
    ) -> Result<types::Size, types::Error> {
        let n = u32::from(fd);
        if VirtualFdTable::is_virtual(n) {
            let mut first = None;
            for iov in iovs.iter() {
                let iov = m.read(iov?)?;
                if iov.buf_len > 0 {
                    first = Some(iov);
                    break;
                }
            }
            let Some(target) = first else { return Ok(0) };
            let mut buf = vec![0u8; target.buf_len as usize];
            let dev = self.vfds.get(n).ok_or(Errno::Badf)?;
            let got = dev.read(&mut buf).await?;
            let got = got.min(buf.len());
            m.copy_from_slice(&buf[..got], target.buf.as_array(got as u32))?;
            return Ok(got as types::Size);
        }
        self.inner.fd_read(m, fd, iovs).await
    }

    async fn fd_pread(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        i: types::IovecArray,
        o: types::Filesize,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_pread(m, fd, i, o).await
    }

    async fn fd_write(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        ciovs: types::CiovecArray,
    ) -> Result<types::Size, types::Error> {
        let n = u32::from(fd);
        if VirtualFdTable::is_virtual(n) {
            let mut data = Vec::new();
            for iov in ciovs.iter() {
                let iov = m.read(iov?)?;
                if iov.buf_len > 0 {
                    data = m.to_vec(iov.buf.as_array(iov.buf_len))?;
                    break;
                }
            }
            let dev = self.vfds.get(n).ok_or(Errno::Badf)?;
            let wrote = dev.write(&data).await?;
            return Ok(wrote.min(data.len()) as types::Size);
        }
        if self.is_out_fd(fd) {
            let want = Self::first_ciovec_len(m, ciovs)?;
            self.reserve_out_bytes(want)?;
            let r = self.inner.fd_write(m, fd, ciovs).await;
            if let Ok(w) = r {
                self.quota.lock().bytes += u64::from(w);
            }
            return r;
        }
        self.inner.fd_write(m, fd, ciovs).await
    }

    async fn fd_pwrite(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        ciovs: types::CiovecArray,
        o: types::Filesize,
    ) -> Result<types::Size, types::Error> {
        if self.is_out_fd(fd) {
            let want = Self::first_ciovec_len(m, ciovs)?;
            self.reserve_out_bytes(want)?;
            let r = self.inner.fd_pwrite(m, fd, ciovs, o).await;
            if let Ok(w) = r {
                self.quota.lock().bytes += u64::from(w);
            }
            return r;
        }
        self.inner.fd_pwrite(m, fd, ciovs, o).await
    }

    fn fd_prestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Prestat, types::Error> {
        self.inner.fd_prestat_get(m, fd)
    }
    fn fd_prestat_dir_name(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<(), types::Error> {
        self.inner.fd_prestat_dir_name(m, fd, p, l)
    }

    async fn fd_renumber(
        &mut self,
        m: &mut GuestMemory<'_>,
        from: types::Fd,
        to: types::Fd,
    ) -> Result<(), types::Error> {
        if VirtualFdTable::is_virtual(u32::from(from)) || VirtualFdTable::is_virtual(u32::from(to))
        {
            return Err(Errno::Notsup.into());
        }
        let r = self.inner.fd_renumber(m, from, to).await;
        if r.is_ok() {
            match self.fds.remove(&u32::from(from)) {
                Some(e) => {
                    self.fds.insert(u32::from(to), e);
                }
                None => {
                    self.fds.remove(&u32::from(to));
                }
            }
        }
        r
    }

    async fn fd_seek(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        o: types::Filedelta,
        w: types::Whence,
    ) -> Result<types::Filesize, types::Error> {
        if VirtualFdTable::is_virtual(u32::from(fd)) {
            return Err(Errno::Spipe.into());
        }
        self.inner.fd_seek(m, fd, o, w).await
    }

    async fn fd_sync(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<(), types::Error> {
        self.inner.fd_sync(m, fd).await
    }
    fn fd_tell(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
    ) -> Result<types::Filesize, types::Error> {
        self.inner.fd_tell(m, fd)
    }
    async fn fd_readdir(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        b: GuestPtr<u8>,
        l: types::Size,
        c: types::Dircookie,
    ) -> Result<types::Size, types::Error> {
        self.inner.fd_readdir(m, fd, b, l, c).await
    }

    async fn path_create_directory(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        delegate_path_op!(
            self,
            FsOp::Mkdir,
            m,
            fd,
            p,
            self.inner.path_create_directory(m, fd, p).await
        )
    }

    async fn path_filestat_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Lookupflags,
        p: GuestPtr<str>,
    ) -> Result<types::Filestat, types::Error> {
        delegate_path_op!(
            self,
            FsOp::Stat,
            m,
            fd,
            p,
            self.inner.path_filestat_get(m, fd, f, p).await
        )
    }

    async fn path_filestat_set_times(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Lookupflags,
        p: GuestPtr<str>,
        a: types::Timestamp,
        b: types::Timestamp,
        s: types::Fstflags,
    ) -> Result<(), types::Error> {
        delegate_path_op!(
            self,
            FsOp::SetTimes,
            m,
            fd,
            p,
            self.inner
                .path_filestat_set_times(m, fd, f, p, a, b, s)
                .await
        )
    }

    async fn path_link(
        &mut self,
        m: &mut GuestMemory<'_>,
        sfd: types::Fd,
        sf: types::Lookupflags,
        sp: GuestPtr<str>,
        tfd: types::Fd,
        tp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        let src = self.check(FsOp::Link, m, sfd, sp, None)?;
        let dst = self.check(FsOp::Link, m, tfd, tp, None)?;
        if let Some(d) = &dst
            && matches!(
                self.mounts[d.mount].kind,
                MountKind::Outputs | MountKind::Work
            )
        {
            // A hard link into /out would let collection read a file from elsewhere.
            self.emit(
                FsOp::Link,
                d.path.clone(),
                None,
                Decision::Deny,
                Some("hard links into outputs are not allowed".into()),
            );
            return Err(Errno::Perm.into());
        }
        let r = self.inner.path_link(m, sfd, sf, sp, tfd, tp).await;
        self.record(FsOp::Link, &src, None, &r);
        self.record(FsOp::Link, &dst, None, &r);
        r
    }

    async fn path_open(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        df: types::Lookupflags,
        p: GuestPtr<str>,
        of: types::Oflags,
        rb: types::Rights,
        ri: types::Rights,
        ff: types::Fdflags,
    ) -> Result<types::Fd, types::Error> {
        let mode = open_mode(of, rb, ff);
        let c = self.check(FsOp::Open, m, fd, p, Some(&mode))?;
        if let Some(chk) = c.as_ref().filter(|c| c.device) {
            let rel = chk
                .path
                .strip_prefix(sandboxd_policy::DEVICE_GUEST_PATH)
                .unwrap_or("")
                .trim_start_matches('/')
                .to_string();
            let path = chk.path.clone();
            return match self.vfds.open(&rel).await {
                Ok(vfd) => {
                    self.emit(
                        FsOp::Open,
                        path,
                        Some(mode),
                        Decision::Allow,
                        Some("device".into()),
                    );
                    Ok(types::Fd::from(vfd))
                }
                Err(e) => {
                    self.emit(
                        FsOp::Open,
                        path,
                        Some(mode),
                        Decision::Deny,
                        Some(format!("device: {}", errno_name(e))),
                    );
                    Err(e.into())
                }
            };
        }
        let mut creating = false;
        if let Some(chk) = &c
            && matches!(
                self.mounts[chk.mount].kind,
                MountKind::Outputs | MountKind::Work
            )
            && of.contains(types::Oflags::CREAT)
            && !self.host_exists(chk)
        {
            let q = self.quota.get();
            if q.files >= q.max_files {
                self.quota_hit("files");
                self.emit(
                    FsOp::Open,
                    chk.path.clone(),
                    Some(mode),
                    Decision::Deny,
                    Some("artifact count limit".into()),
                );
                return Err(Errno::Nospc.into());
            }
            creating = true;
        }
        let r = self.inner.path_open(m, fd, df, p, of, rb, ri, ff).await;
        self.record(FsOp::Open, &c, Some(mode), &r);
        if let (Ok(new_fd), Some(chk)) = (&r, c) {
            if creating {
                self.quota.lock().files += 1;
            }
            self.fds.insert(
                u32::from(*new_fd),
                FdEntry {
                    mount: chk.mount,
                    path: chk.path,
                },
            );
        }
        r
    }

    async fn path_readlink(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
        b: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<types::Size, types::Error> {
        delegate_path_op!(
            self,
            FsOp::Readlink,
            m,
            fd,
            p,
            self.inner.path_readlink(m, fd, p, b, l).await
        )
    }

    async fn path_remove_directory(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        delegate_path_op!(
            self,
            FsOp::Rmdir,
            m,
            fd,
            p,
            self.inner.path_remove_directory(m, fd, p).await
        )
    }

    async fn path_rename(
        &mut self,
        m: &mut GuestMemory<'_>,
        sfd: types::Fd,
        sp: GuestPtr<str>,
        dfd: types::Fd,
        dp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        let src = self.check(FsOp::Rename, m, sfd, sp, None)?;
        let dst = self.check(FsOp::Rename, m, dfd, dp, None)?;
        let r = self.inner.path_rename(m, sfd, sp, dfd, dp).await;
        self.record(FsOp::Rename, &src, None, &r);
        self.record(FsOp::Rename, &dst, None, &r);
        r
    }

    async fn path_symlink(
        &mut self,
        m: &mut GuestMemory<'_>,
        sp: GuestPtr<str>,
        fd: types::Fd,
        dp: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        // Only the new link's location is a path we resolve; the target text is opaque here and
        // cap-std refuses to follow links out of a preopen.
        delegate_path_op!(
            self,
            FsOp::Symlink,
            m,
            fd,
            dp,
            self.inner.path_symlink(m, sp, fd, dp).await
        )
    }

    async fn path_unlink_file(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        p: GuestPtr<str>,
    ) -> Result<(), types::Error> {
        delegate_path_op!(
            self,
            FsOp::Unlink,
            m,
            fd,
            p,
            self.inner.path_unlink_file(m, fd, p).await
        )
    }

    async fn poll_oneoff(
        &mut self,
        m: &mut GuestMemory<'_>,
        s: GuestPtr<types::Subscription>,
        e: GuestPtr<types::Event>,
        n: types::Size,
    ) -> Result<types::Size, types::Error> {
        self.inner.poll_oneoff(m, s, e, n).await
    }
    fn proc_exit(&mut self, m: &mut GuestMemory<'_>, status: types::Exitcode) -> wasmtime::Error {
        self.inner.proc_exit(m, status)
    }
    fn proc_raise(
        &mut self,
        m: &mut GuestMemory<'_>,
        s: types::Signal,
    ) -> Result<(), types::Error> {
        self.inner.proc_raise(m, s)
    }
    fn sched_yield(&mut self, m: &mut GuestMemory<'_>) -> Result<(), types::Error> {
        self.inner.sched_yield(m)
    }
    fn random_get(
        &mut self,
        m: &mut GuestMemory<'_>,
        b: GuestPtr<u8>,
        l: types::Size,
    ) -> Result<(), types::Error> {
        self.inner.random_get(m, b, l)
    }
    fn sock_accept(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        f: types::Fdflags,
    ) -> Result<types::Fd, types::Error> {
        self.inner.sock_accept(m, fd, f)
    }
    fn sock_recv(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        d: types::IovecArray,
        f: types::Riflags,
    ) -> Result<(types::Size, types::Roflags), types::Error> {
        self.inner.sock_recv(m, fd, d, f)
    }
    fn sock_send(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        d: types::CiovecArray,
        f: types::Siflags,
    ) -> Result<types::Size, types::Error> {
        self.inner.sock_send(m, fd, d, f)
    }
    fn sock_shutdown(
        &mut self,
        m: &mut GuestMemory<'_>,
        fd: types::Fd,
        h: types::Sdflags,
    ) -> Result<(), types::Error> {
        self.inner.sock_shutdown(m, fd, h)
    }
}
