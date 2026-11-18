//! Audit sinks (design §2–§3, rules A1, A2, A6, A7; fail-closed health per Q6).

use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crate::{
    event::{AuditEvent, EventKind},
    redact::Redactor,
};

/// Destination for audit events. Implementations must never block or panic in `emit`.
pub trait AuditSink: Send + Sync + 'static {
    /// Record an event. Infallible and non-blocking for the caller (rule A1).
    fn emit(&self, ev: AuditEvent);
    /// `false` while events cannot be persisted. The server rejects new runs then (fail closed).
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Discards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;
impl AuditSink for NullSink {
    fn emit(&self, _ev: AuditEvent) {}
}

/// Sends every event to several sinks. Healthy only if all are healthy.
#[derive(Default)]
pub struct FanoutSink(pub Vec<Arc<dyn AuditSink>>);
impl AuditSink for FanoutSink {
    fn emit(&self, ev: AuditEvent) {
        if let Some((last, rest)) = self.0.split_last() {
            for s in rest {
                s.emit(ev.clone());
            }
            last.emit(ev);
        }
    }
    fn is_healthy(&self) -> bool {
        self.0.iter().all(|s| s.is_healthy())
    }
}
impl std::fmt::Debug for FanoutSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FanoutSink({} sinks)", self.0.len())
    }
}

/// Collects events in memory (tests in this and downstream crates).
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Default)]
pub struct MemorySink(Mutex<Vec<AuditEvent>>);
#[cfg(any(test, feature = "testing"))]
impl MemorySink {
    /// Snapshot of everything emitted so far.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}
#[cfg(any(test, feature = "testing"))]
impl AuditSink for MemorySink {
    fn emit(&self, ev: AuditEvent) {
        if let Ok(mut v) = self.0.lock() {
            v.push(ev);
        }
    }
}

/// Settings for [`JsonlSink`].
#[derive(Debug, Clone)]
pub struct JsonlOptions {
    /// Queue capacity before events are dropped and counted (default 8192).
    pub queue: usize,
    /// Max serialized bytes held while the destination is failing (default 8 MiB).
    pub max_pending_bytes: usize,
    /// Retry interval while unhealthy (default 1s).
    pub retry: Duration,
    /// How long `shutdown` waits for the writer to drain (default 2s).
    pub shutdown_timeout: Duration,
}
impl Default for JsonlOptions {
    fn default() -> Self {
        Self {
            queue: 8192,
            max_pending_bytes: 8 << 20,
            retry: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(2),
        }
    }
}

enum Msg {
    Event(Box<AuditEvent>),
    Shutdown(SyncSender<()>),
}

struct Shared {
    dropped: AtomicU64,
    healthy: AtomicBool,
}

/// JSON Lines sink: bounded queue → dedicated writer thread → file or stdout.
pub struct JsonlSink {
    tx: SyncSender<Msg>,
    shared: Arc<Shared>,
    shutdown_timeout: Duration,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for JsonlSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonlSink")
            .field("healthy", &self.is_healthy())
            .field(
                "dropped_pending",
                &self.shared.dropped.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl JsonlSink {
    /// Append to `path`, creating it (mode 0600 on Unix) if missing (rule A7).
    pub fn to_file(path: &Path, redactor: Redactor, opts: JsonlOptions) -> io::Result<Self> {
        let mut oo = OpenOptions::new();
        oo.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            oo.mode(0o600);
        }
        let file = oo.open(path)?;
        Ok(Self::to_writer(Box::new(file), redactor, opts))
    }

    /// Write to the process's stdout.
    pub fn to_stdout(redactor: Redactor, opts: JsonlOptions) -> Self {
        Self::to_writer(Box::new(io::stdout()), redactor, opts)
    }

    /// Write to any destination (tests, custom transports).
    pub fn to_writer(out: Box<dyn Write + Send>, redactor: Redactor, opts: JsonlOptions) -> Self {
        let (tx, rx) = mpsc::sync_channel(opts.queue.max(1));
        let shared = Arc::new(Shared {
            dropped: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
        });
        let w = Writer {
            out,
            redactor,
            shared: shared.clone(),
            pending: Vec::new(),
            max_pending: opts.max_pending_bytes,
            retry: opts.retry,
            last_stderr_report: None,
        };
        let worker = std::thread::Builder::new()
            .name("sandboxd-audit".into())
            .spawn(move || w.run(rx))
            .expect("spawn audit writer thread");
        Self {
            tx,
            shared,
            shutdown_timeout: opts.shutdown_timeout,
            worker: Mutex::new(Some(worker)),
        }
    }

    /// Drain the queue, flush, and stop the writer (rule A6). Idempotent.
    pub fn shutdown(&self) {
        let Some(handle) = self.worker.lock().ok().and_then(|mut w| w.take()) else {
            return;
        };
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        let deadline = Instant::now() + self.shutdown_timeout;
        let mut msg = Msg::Shutdown(ack_tx);
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Full(m)) if Instant::now() < deadline => {
                    msg = m;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if ack_rx.recv_timeout(left).is_ok() {
            let _ = handle.join();
        }
    }
}

impl AuditSink for JsonlSink {
    fn emit(&self, ev: AuditEvent) {
        if self.tx.try_send(Msg::Event(Box::new(ev))).is_err() {
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn is_healthy(&self) -> bool {
        self.shared.healthy.load(Ordering::Acquire)
    }
}

impl Drop for JsonlSink {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Writer {
    out: Box<dyn Write + Send>,
    redactor: Redactor,
    shared: Arc<Shared>,
    /// Serialized lines not yet confirmed written (kept while the destination fails).
    pending: Vec<u8>,
    max_pending: usize,
    retry: Duration,
    last_stderr_report: Option<Instant>,
}

impl Writer {
    fn run(mut self, rx: Receiver<Msg>) {
        loop {
            // Block for the first message (or time out to retry a failing destination).
            let first = if self.pending.is_empty() {
                match rx.recv() {
                    Ok(m) => Some(m),
                    Err(_) => break,
                }
            } else {
                match rx.recv_timeout(self.retry) {
                    Ok(m) => Some(m),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            };
            let mut ack = None;
            if let Some(m) = first {
                ack = self.take(m);
                // Drain whatever else is queued into the same batch (rule A2).
                while ack.is_none() {
                    match rx.try_recv() {
                        Ok(m) => ack = self.take(m),
                        Err(_) => break,
                    }
                }
            }
            let dropped = self.shared.dropped.swap(0, Ordering::Relaxed);
            if dropped > 0 {
                self.push(&AuditEvent::new(EventKind::Dropped { count: dropped }));
            }
            self.flush();
            if let Some(ack) = ack {
                let _ = ack.send(());
                return;
            }
        }
        self.flush();
    }

    /// Queue one message; returns the ack channel on shutdown.
    fn take(&mut self, m: Msg) -> Option<SyncSender<()>> {
        match m {
            Msg::Event(ev) => {
                self.push(&ev);
                None
            }
            Msg::Shutdown(ack) => Some(ack),
        }
    }

    fn push(&mut self, ev: &AuditEvent) {
        let line = ev.to_json_line(&self.redactor);
        if self.pending.len() + line.len() + 1 > self.max_pending {
            // Destination has been failing long enough to fill the buffer: count as dropped.
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.pending.extend_from_slice(line.as_bytes());
        self.pending.push(b'\n');
    }

    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        match self
            .out
            .write_all(&self.pending)
            .and_then(|()| self.out.flush())
        {
            Ok(()) => {
                self.pending.clear();
                self.shared.healthy.store(true, Ordering::Release);
            }
            Err(e) => {
                self.shared.healthy.store(false, Ordering::Release);
                let now = Instant::now();
                let due = self
                    .last_stderr_report
                    .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(60));
                if due {
                    eprintln!(
                        "sandboxd: audit log write failed ({e}); new runs are rejected until it recovers"
                    );
                    self.last_stderr_report = Some(now);
                }
            }
        }
    }
}
