//! `/dev/sandbox/tcp/<host>:<port>`: allowlisted, SSRF-checked byte streams (design §6).

use std::{net::IpAddr, sync::Arc, time::Instant};

use sandboxd_audit::Decision;
use sandboxd_vfs::{DeviceFuture, VirtualDevice};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use wasmtime_wasi::p1::types::Errno;

use crate::{
    RunInner,
    ip::permitted,
    resolve::{ResolveError, resolve_checked},
    target::match_tcp,
};

pub(crate) struct TcpDevice {
    run: Arc<RunInner>,
    host: String,
    literal: Option<IpAddr>,
    port: u16,
    stream: Option<TcpStream>,
    peer: Option<IpAddr>,
    started: Instant,
    out: u64,
    inn: u64,
    closed: bool,
}

impl TcpDevice {
    /// Factory: synchronous allowlist check; the connect happens in `opened`.
    pub(crate) fn create(run: Arc<RunInner>, rel: &str) -> Result<Box<dyn VirtualDevice>, Errno> {
        let spec = rel.strip_prefix("tcp/").unwrap_or("");
        match match_tcp(&run.net.tcp, spec) {
            Ok((_, host, literal, port)) => Ok(Box::new(TcpDevice {
                run,
                host,
                literal,
                port,
                stream: None,
                peer: None,
                started: Instant::now(),
                out: 0,
                inn: 0,
                closed: false,
            })),
            Err(reason) => {
                let started = Instant::now();
                run.emit_tcp(spec, None, 0, 0, 0, started, Decision::Deny, Some(reason));
                Err(Errno::Acces)
            }
        }
    }

    fn deny(&mut self, reason: String, errno: Errno) -> Errno {
        self.closed = true;
        self.run.emit_tcp(
            &self.host,
            self.peer,
            self.port,
            0,
            0,
            self.started,
            Decision::Deny,
            Some(reason),
        );
        errno
    }

    fn idle_budget(&self) -> std::time::Duration {
        self.run.budget(self.run.net.request_timeout)
    }
}

impl VirtualDevice for TcpDevice {
    fn opened(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async move {
            if !self.run.take_request() {
                return Err(self.deny(
                    format!(
                        "network request quota ({}) exhausted",
                        self.run.net.max_requests
                    ),
                    Errno::Acces,
                ));
            }
            let addrs = if let Some(ip) = self.literal {
                if let Err(why) = permitted(
                    ip,
                    self.run.net.allow_private_ips,
                    self.run.explicit_ip_rule(ip),
                ) {
                    self.peer = Some(ip);
                    return Err(self.deny(why, Errno::Acces));
                }
                vec![std::net::SocketAddr::new(ip, self.port)]
            } else {
                match resolve_checked(&self.host, self.port, self.run.net.allow_private_ips).await {
                    Ok(a) => a,
                    Err(ResolveError::Ssrf(m)) => return Err(self.deny(m, Errno::Acces)),
                    Err(ResolveError::Dns(m)) => return Err(self.deny(m, Errno::Noent)),
                }
            };
            let budget = self.run.budget(self.run.net.connect_timeout);
            let mut last = Errno::Connrefused;
            for addr in addrs {
                match tokio::time::timeout(budget, TcpStream::connect(addr)).await {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        self.peer = Some(addr.ip());
                        self.stream = Some(s);
                        self.started = Instant::now();
                        return Ok(());
                    }
                    Ok(Err(e)) => {
                        last = match e.kind() {
                            std::io::ErrorKind::ConnectionRefused => Errno::Connrefused,
                            _ => Errno::Hostunreach,
                        }
                    }
                    Err(_) => last = Errno::Timedout,
                }
            }
            let reason = format!("connect to {}:{} failed ({last:?})", self.host, self.port);
            Err(self.deny(reason, last))
        })
    }

    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            let budget = self.idle_budget();
            let stream = self.stream.as_mut().ok_or(Errno::Notconn)?;
            let n = match tokio::time::timeout(budget, stream.read(buf)).await {
                Err(_) => {
                    self.run.mark_limit();
                    return Err(Errno::Timedout);
                }
                Ok(Err(_)) => return Err(Errno::Connreset),
                Ok(Ok(n)) => n,
            };
            self.inn += n as u64;
            if !self.run.add_in(n as u64) {
                return Err(Errno::Io);
            }
            Ok(n)
        })
    }

    fn write<'a>(&'a mut self, data: &'a [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            if !self.run.add_out(data.len() as u64) {
                return Err(Errno::Io);
            }
            let budget = self.idle_budget();
            let stream = self.stream.as_mut().ok_or(Errno::Notconn)?;
            let n = match tokio::time::timeout(budget, stream.write(data)).await {
                Err(_) => {
                    self.run.mark_limit();
                    return Err(Errno::Timedout);
                }
                Ok(Err(_)) => return Err(Errno::Pipe),
                Ok(Ok(n)) => n,
            };
            self.out += n as u64;
            Ok(n)
        })
    }

    fn close(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async move {
            if let Some(mut s) = self.stream.take() {
                let _ = s.shutdown().await;
            }
            if !self.closed {
                self.closed = true;
                self.run.emit_tcp(
                    &self.host,
                    self.peer,
                    self.port,
                    self.out,
                    self.inn,
                    self.started,
                    Decision::Allow,
                    None,
                );
            }
            Ok(())
        })
    }
}

impl Drop for TcpDevice {
    fn drop(&mut self) {
        if !self.closed && self.stream.is_some() {
            self.run.emit_tcp(
                &self.host,
                self.peer,
                self.port,
                self.out,
                self.inn,
                self.started,
                Decision::Allow,
                Some("closed at run end".into()),
            );
        }
    }
}
