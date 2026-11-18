//! Capped, streaming stdout/stderr (U4 design §4).

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use sandboxd_audit::LimitKind;
use tokio::{io::AsyncWrite, sync::mpsc::UnboundedSender};
use wasmtime_wasi::cli::{IsTerminal, StdoutStream};

use crate::types::RunEvent;

#[derive(Debug, Default)]
struct State {
    buf: Vec<u8>,
    truncated: bool,
}

/// Collects up to `cap` bytes, forwards each chunk as a [`RunEvent`], then fails writes.
#[derive(Clone)]
pub(crate) struct CappedStream {
    state: Arc<Mutex<State>>,
    cap: usize,
    kind: LimitKind,
    tx: Option<UnboundedSender<RunEvent>>,
}

impl CappedStream {
    pub(crate) fn new(cap: u64, kind: LimitKind, tx: Option<UnboundedSender<RunEvent>>) -> Self {
        Self {
            state: Arc::default(),
            cap: usize::try_from(cap).unwrap_or(usize::MAX),
            kind,
            tx,
        }
    }

    /// (bytes, truncated)
    pub(crate) fn take(&self) -> (Vec<u8>, bool) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (std::mem::take(&mut s.buf), s.truncated)
    }

    pub(crate) fn truncated(&self) -> bool {
        self.state.lock().map(|s| s.truncated).unwrap_or(true)
    }

    fn accept(&self, data: &[u8]) -> io::Result<usize> {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.truncated {
            return Err(io::Error::other("output limit reached"));
        }
        let room = self.cap.saturating_sub(s.buf.len());
        let n = data.len().min(room);
        s.buf.extend_from_slice(&data[..n]);
        if n > 0
            && let Some(tx) = &self.tx
        {
            let chunk = Bytes::copy_from_slice(&data[..n]);
            let ev = if self.kind == LimitKind::Stdout {
                RunEvent::Stdout(chunk)
            } else {
                RunEvent::Stderr(chunk)
            };
            let _ = tx.send(ev);
        }
        if n < data.len() {
            s.truncated = true;
            if let Some(tx) = &self.tx {
                let _ = tx.send(RunEvent::LimitHit(self.kind));
            }
            if n == 0 {
                return Err(io::Error::other("output limit reached"));
            }
        }
        Ok(n)
    }
}

impl IsTerminal for CappedStream {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for CappedStream {
    fn async_stream(&self) -> Box<dyn AsyncWrite + Send + Sync> {
        Box::new(Writer(self.clone()))
    }
}

struct Writer(CappedStream);

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.accept(buf))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_and_streams() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let s = CappedStream::new(5, LimitKind::Stdout, Some(tx));
        assert_eq!(s.accept(b"abc").ok(), Some(3));
        assert_eq!(s.accept(b"defg").ok(), Some(2));
        assert!(s.accept(b"h").is_err());
        assert!(s.truncated());
        assert_eq!(s.take(), (b"abcde".to_vec(), true));
        let mut evs = Vec::new();
        while let Ok(e) = rx.try_recv() {
            evs.push(e);
        }
        assert!(matches!(&evs[0], RunEvent::Stdout(b) if b.as_ref() == b"abc"));
        assert!(matches!(&evs[1], RunEvent::Stdout(b) if b.as_ref() == b"de"));
        assert!(matches!(evs[2], RunEvent::LimitHit(LimitKind::Stdout)));
    }
}
