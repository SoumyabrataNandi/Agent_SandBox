//! Virtual device seam (ADR-002). The network broker (`sandboxd-net`) plugs `/dev/sandbox/http`
//! and `/dev/sandbox/tcp/<host>:<port>` in here; the runtime adds `/dev/sandbox/info`.

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
    /// Called once right after the factory created the device, before the fd is handed to the
    /// guest. Async setup (e.g. a TCP connect) happens here so failures surface at `open`.
    fn opened(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// A read-only device that returns fixed bytes (e.g. `/dev/sandbox/info`). Writes fail `EBADF`.
#[derive(Debug, Clone)]
pub struct StaticDevice {
    data: std::sync::Arc<[u8]>,
    off: usize,
}

impl StaticDevice {
    /// A device that reads `data` and then end-of-stream.
    pub fn new(data: impl Into<std::sync::Arc<[u8]>>) -> Self {
        Self {
            data: data.into(),
            off: 0,
        }
    }
}

impl VirtualDevice for StaticDevice {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            let n = (self.data.len() - self.off).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.off..self.off + n]);
            self.off += n;
            Ok(n)
        })
    }
    fn write<'a>(&'a mut self, _buf: &'a [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async { Err(Errno::Badf) })
    }
    fn close(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
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
    pub async fn open(&mut self, rel: &str) -> Result<u32, Errno> {
        let family = rel.split('/').next().unwrap_or_default();
        let factory = self.factories.get(family).ok_or(Errno::Noent)?;
        let mut dev = factory(rel)?;
        dev.opened().await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_device_reads_once_and_refuses_writes() {
        let mut t = VirtualFdTable::default();
        t.register(
            "info",
            Box::new(|rel: &str| {
                if rel == "info" {
                    Ok(Box::new(StaticDevice::new(b"abcdef".to_vec())) as Box<dyn VirtualDevice>)
                } else {
                    Err(Errno::Noent)
                }
            }),
        );
        assert_eq!(t.open("info/x").await.err(), Some(Errno::Noent));
        assert_eq!(t.open("http").await.err(), Some(Errno::Noent));
        let fd = t.open("info").await.expect("open");
        let dev = t.get(fd).expect("dev");
        let mut buf = [0u8; 4];
        assert_eq!(dev.read(&mut buf).await, Ok(4));
        assert_eq!(&buf, b"abcd");
        assert_eq!(dev.read(&mut buf).await, Ok(2));
        assert_eq!(dev.read(&mut buf).await, Ok(0));
        assert_eq!(dev.write(b"x").await, Err(Errno::Badf));
    }
}
