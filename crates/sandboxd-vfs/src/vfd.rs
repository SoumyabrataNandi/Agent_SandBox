//! Virtual device seam (ADR-002). No devices are registered in this cycle; the Phase 4 network
//! broker plugs `/dev/sandbox/http` and `/dev/sandbox/tcp/<host>:<port>` in here.

use std::{collections::BTreeMap, fmt, future::Future, pin::Pin};

use wasmtime_wasi::p1::types::Errno;

/// Boxed future returned by device operations (trait objects can't use `async fn`).
pub type DeviceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, Errno>> + Send + 'a>>;

/// A host-implemented file the guest can open under `/dev/sandbox`.
pub trait VirtualDevice: Send {
    /// Read into `buf`; `Ok(0)` is end-of-stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> DeviceFuture<'a, usize>;
    /// Write from `buf`; returns bytes accepted.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> DeviceFuture<'a, usize>;
    /// Called once when the guest closes the fd.
    fn close(&mut self) -> DeviceFuture<'_, ()>;
}

/// Opens a device for a path relative to `/dev/sandbox` (e.g. `http`, `tcp/db:5432`).
pub type DeviceFactory = Box<dyn Fn(&str) -> Result<Box<dyn VirtualDevice>, Errno> + Send + Sync>;

/// First fd number used for virtual devices; far above anything wasmtime-wasi allocates.
pub const VFD_BASE: u32 = 0x4000_0000;

/// Registry of device factories (by first path component) and open virtual fds.
#[derive(Default)]
pub struct VirtualFdTable {
    factories: BTreeMap<String, DeviceFactory>,
    open: BTreeMap<u32, Box<dyn VirtualDevice>>,
    next: u32,
}

impl fmt::Debug for VirtualFdTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VirtualFdTable")
            .field("devices", &self.factories.keys().collect::<Vec<_>>())
            .field("open", &self.open.len())
            .finish()
    }
}

impl VirtualFdTable {
    /// Register a device family, e.g. `"http"` or `"tcp"`.
    pub fn register(&mut self, name: impl Into<String>, factory: DeviceFactory) {
        self.factories.insert(name.into(), factory);
    }

    /// `true` if `fd` is in the virtual range.
    pub fn is_virtual(fd: u32) -> bool {
        fd >= VFD_BASE
    }

    /// Open `rel` (path under `/dev/sandbox`). `ENOENT` if no device family matches.
    pub fn open(&mut self, rel: &str) -> Result<u32, Errno> {
        let family = rel.split('/').next().unwrap_or_default();
        let factory = self.factories.get(family).ok_or(Errno::Noent)?;
        let dev = factory(rel)?;
        let fd = VFD_BASE + self.next;
        self.next = self.next.checked_add(1).ok_or(Errno::Mfile)?;
        self.open.insert(fd, dev);
        Ok(fd)
    }

    /// Mutable access to an open device.
    pub fn get(&mut self, fd: u32) -> Option<&mut Box<dyn VirtualDevice>> {
        self.open.get_mut(&fd)
    }

    /// Remove and return a device (on close).
    pub fn take(&mut self, fd: u32) -> Option<Box<dyn VirtualDevice>> {
        self.open.remove(&fd)
    }
}
