//! Network broker for sandboxd (cycle 2, unit C2-U2).
//!
//! The guest never gets a socket. It opens `/dev/sandbox/http` (one request/response exchange
//! per fd, ADR-C2-2) or `/dev/sandbox/tcp/<host>:<port>` (a byte stream). This crate implements
//! those devices: URL canonicalization, allowlist matching, SSRF checks with IP pinning,
//! broker-managed redirects, quotas, TLS via the OS trust store, an operator proxy, and
//! `net.request` / `net.connect` audit events that never contain bodies or header values.
//!
//! Design: `aidlc-docs/cycle-2/construction/c2-u2-net-broker/design.md`.

#![forbid(unsafe_code)]

mod frame;
mod http;
mod ip;
mod resolve;
mod target;
mod tcp;

use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::Instant,
};

use sandboxd_audit::{AuditEvent, AuditSink, Decision, EventKind, LimitKind, RunId};
use sandboxd_policy::{NetworkPolicy, Policy};
use sandboxd_vfs::{VirtualDevice, VirtualFdTable};
use wasmtime_wasi::p1::types::Errno;

pub use frame::{
    Decoded, FrameError, MAX_HEADER_BYTES, MAX_HEADER_VALUE, MAX_HEADERS, RequestHeader,
    ResponseHeader, decode_request, encode_request, encode_response,
};
pub use ip::{IpClass, classify, permitted};
pub use target::{Target, match_http, match_tcp, parse_target, prefix_matches};

/// Install the process-wide rustls crypto provider (`ring`; ADR-C2-1 amendment) if none is set.
///
/// Every reqwest client in the process needs it once TLS is compiled in, including clients that
/// other crates create (feature unification). Call it early in `main`; it is idempotent.
pub fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Errors building the broker or a run's client.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("invalid proxy {0:?}: {1}")]
    Proxy(String, String),
    #[error("extra CA file: {0}")]
    Ca(String),
    #[error("http client: {0}")]
    Client(String),
}

/// Server-wide broker settings (from `sandboxd.toml [network]`).
#[derive(Debug, Clone, Default)]
pub struct BrokerConfig {
    pub proxy: Option<String>,
    pub no_proxy: Vec<String>,
    pub use_env_proxy: bool,
    /// PEM bundle added to the OS trust store.
    pub extra_ca_pem: Option<Vec<u8>>,
}

struct BrokerInner {
    proxy: Option<(reqwest::Proxy, String)>,
    extra_certs: Vec<reqwest::Certificate>,
}

/// Process-wide broker: validated proxy + trust settings. Cheap to clone.
#[derive(Clone)]
pub struct Broker {
    inner: Arc<BrokerInner>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("proxy", &self.inner.proxy.as_ref().map(|(_, h)| h))
            .field("extra_certs", &self.inner.extra_certs.len())
            .finish()
    }
}

fn env_any(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
}

impl Broker {
    /// Validate settings eagerly so a bad proxy or CA file fails at server start.
    pub fn new(cfg: BrokerConfig) -> Result<Broker, NetError> {
        ensure_crypto_provider();

        let (proxy_url, no_proxy) = match (&cfg.proxy, cfg.use_env_proxy) {
            (Some(p), _) => (Some(p.clone()), cfg.no_proxy.join(",")),
            (None, true) => (
                env_any(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]),
                env_any(&["NO_PROXY", "no_proxy"]).unwrap_or_default(),
            ),
            (None, false) => (None, String::new()),
        };
        let proxy = match proxy_url {
            None => None,
            Some(u) => {
                let parsed =
                    url::Url::parse(&u).map_err(|e| NetError::Proxy(u.clone(), e.to_string()))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(NetError::Proxy(u, "must be http:// or https://".into()));
                }
                let host = parsed
                    .host_str()
                    .ok_or_else(|| NetError::Proxy(u.clone(), "no host".into()))?
                    .to_ascii_lowercase();
                let p = reqwest::Proxy::all(u.as_str())
                    .map_err(|e| NetError::Proxy(u.clone(), e.to_string()))?
                    .no_proxy(reqwest::NoProxy::from_string(&no_proxy));
                Some((p, host))
            }
        };
        let extra_certs = match &cfg.extra_ca_pem {
            None => Vec::new(),
            Some(pem) => {
                let certs = reqwest::Certificate::from_pem_bundle(pem)
                    .map_err(|e| NetError::Ca(e.to_string()))?;
                if certs.is_empty() {
                    return Err(NetError::Ca("no certificates found in PEM".into()));
                }
                certs
            }
        };
        Ok(Broker {
            inner: Arc::new(BrokerInner { proxy, extra_certs }),
        })
    }

    /// Per-run state, or `None` when the policy grants no egress (zero cost).
    pub fn for_run(&self, policy: &Policy, ctx: RunCtx) -> Result<Option<RunNet>, NetError> {
        let net = policy.network().clone();
        if !net.grants_anything() {
            return Ok(None);
        }
        let client = if net.http.is_empty() {
            None
        } else {
            let resolver = resolve::PinningResolver {
                allow_private: net.allow_private_ips,
                proxy_host: self.inner.proxy.as_ref().map(|(_, h)| h.clone()),
            };
            let mut b = reqwest::Client::builder()
                .dns_resolver(Arc::new(resolver))
                .redirect(reqwest::redirect::Policy::none()) // broker-managed redirects (H6)
                .retry(reqwest::retry::never()) // a silent retry would be an un-audited request
                .referer(false)
                .connect_timeout(net.connect_timeout)
                .pool_max_idle_per_host(4);
            if !self.inner.extra_certs.is_empty() {
                b = b.tls_certs_merge(self.inner.extra_certs.clone());
            }
            b = match &self.inner.proxy {
                Some((p, _)) => b.proxy(p.clone()),
                None => b.no_proxy(), // never use OS/system proxies implicitly (FR-N9)
            };
            Some(b.build().map_err(|e| NetError::Client(e.to_string()))?)
        };
        let quota = Quota {
            max_requests: net.max_requests,
            max_total: net.max_total_bytes.bytes(),
            ..Quota::default()
        };
        Ok(Some(RunNet {
            inner: Arc::new(RunInner {
                net,
                client,
                ctx,
                quota,
                proxy_active: self.inner.proxy.is_some(),
            }),
        }))
    }
}

/// Run identity and limits the broker needs.
#[derive(Clone)]
pub struct RunCtx {
    pub run_id: RunId,
    pub policy: String,
    /// The run's wall-clock deadline: network time counts against it (N1.2).
    pub deadline: Instant,
    pub audit: Arc<dyn AuditSink>,
}

impl std::fmt::Debug for RunCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunCtx")
            .field("run_id", &self.run_id)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub(crate) struct Quota {
    max_requests: u32,
    max_total: u64,
    requests: AtomicU32,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    hit: AtomicBool,
}

pub(crate) struct RunInner {
    pub(crate) net: NetworkPolicy,
    pub(crate) client: Option<reqwest::Client>,
    pub(crate) ctx: RunCtx,
    quota: Quota,
    pub(crate) proxy_active: bool,
}

impl RunInner {
    /// Count one request/connection; `false` (and a `limit.hit`) when over quota.
    pub(crate) fn take_request(&self) -> bool {
        let n = self.quota.requests.fetch_add(1, Ordering::SeqCst) + 1;
        if n > self.quota.max_requests {
            self.limit_hit(u64::from(self.quota.max_requests), u64::from(n));
            return false;
        }
        true
    }

    fn add_bytes(&self, counter: &AtomicU64, n: u64) -> bool {
        counter.fetch_add(n, Ordering::SeqCst);
        let total = self.quota.bytes_in.load(Ordering::SeqCst)
            + self.quota.bytes_out.load(Ordering::SeqCst);
        if total > self.quota.max_total {
            self.limit_hit(self.quota.max_total, total);
            return false;
        }
        true
    }

    pub(crate) fn add_out(&self, n: u64) -> bool {
        self.add_bytes(&self.quota.bytes_out, n)
    }

    pub(crate) fn add_in(&self, n: u64) -> bool {
        self.add_bytes(&self.quota.bytes_in, n)
    }

    pub(crate) fn limit_hit(&self, limit: u64, observed: u64) {
        if !self.quota.hit.swap(true, Ordering::SeqCst) {
            self.emit(EventKind::LimitHit {
                kind: LimitKind::Network,
                limit,
                observed,
            });
        }
    }

    pub(crate) fn mark_limit(&self) {
        self.quota.hit.store(true, Ordering::SeqCst);
    }

    pub(crate) fn emit(&self, kind: EventKind) {
        self.ctx.audit.emit(
            AuditEvent::new(kind)
                .run(self.ctx.run_id)
                .policy(self.ctx.policy.clone()),
        );
    }

    /// Time left for network I/O, bounded by `cap`.
    pub(crate) fn budget(&self, cap: std::time::Duration) -> std::time::Duration {
        self.ctx
            .deadline
            .saturating_duration_since(Instant::now())
            .min(cap)
    }

    pub(crate) fn explicit_ip_rule(&self, ip: IpAddr) -> bool {
        target::explicit_ip_rule(&self.net.http, ip)
            || self
                .net
                .tcp
                .iter()
                .any(|r| r.host.parse::<IpAddr>().is_ok_and(|r| r == ip))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_tcp(
        &self,
        host: &str,
        ip: Option<IpAddr>,
        port: u16,
        out: u64,
        inn: u64,
        started: Instant,
        decision: Decision,
        reason: Option<String>,
    ) {
        self.emit(EventKind::NetConnect {
            host: host.into(),
            ip: ip.map(|i| i.to_string()),
            port,
            bytes_out: out,
            bytes_in: inn,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            decision,
            reason,
        });
    }
}

/// What the broker did during a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetReport {
    pub requests: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub limit_hit: bool,
}

/// Per-run broker state (own client and connection pool; ADR-C2-5).
#[derive(Clone)]
pub struct RunNet {
    inner: Arc<RunInner>,
}

impl std::fmt::Debug for RunNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunNet")
            .field("ctx", &self.inner.ctx)
            .finish_non_exhaustive()
    }
}

impl RunNet {
    /// Register the device families this policy grants: `http` and/or `tcp`.
    pub fn register(&self, vfds: &mut VirtualFdTable) {
        if self.inner.client.is_some() {
            let run = self.inner.clone();
            vfds.register(
                "http",
                Box::new(move |rel: &str| {
                    if rel == "http" {
                        Ok(Box::new(http::HttpDevice::new(run.clone())) as Box<dyn VirtualDevice>)
                    } else {
                        Err(Errno::Noent)
                    }
                }),
            );
        }
        if !self.inner.net.tcp.is_empty() {
            let run = self.inner.clone();
            vfds.register(
                "tcp",
                Box::new(move |rel: &str| tcp::TcpDevice::create(run.clone(), rel)),
            );
        }
    }

    /// Counters for the run result. Open TCP sessions are audited when their devices drop.
    pub fn finish(&self) -> NetReport {
        let q = &self.inner.quota;
        NetReport {
            requests: q
                .requests
                .load(Ordering::SeqCst)
                .min(q.max_requests.saturating_add(1)),
            bytes_in: q.bytes_in.load(Ordering::SeqCst),
            bytes_out: q.bytes_out.load(Ordering::SeqCst),
            limit_hit: q.hit.load(Ordering::SeqCst),
        }
    }

    /// Direct access to an HTTP device (tests and diagnostics).
    pub fn http_device(&self) -> Option<Box<dyn VirtualDevice>> {
        self.inner
            .client
            .as_ref()
            .map(|_| Box::new(http::HttpDevice::new(self.inner.clone())) as Box<dyn VirtualDevice>)
    }

    /// Direct access to a TCP device for `host:port` (tests and diagnostics).
    pub fn tcp_device(&self, spec: &str) -> Result<Box<dyn VirtualDevice>, Errno> {
        tcp::TcpDevice::create(self.inner.clone(), &format!("tcp/{spec}"))
    }
}
