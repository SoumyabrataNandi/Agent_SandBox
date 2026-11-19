//! DNS resolution with SSRF checks and IP pinning (design §4; FR-N5).

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::ip::permitted;

/// Raised from the resolver so the exchange can report `SSRF` precisely.
#[derive(Debug, Clone)]
pub struct SsrfBlocked(pub String);
impl fmt::Display for SsrfBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SsrfBlocked {}

/// Name did not resolve.
#[derive(Debug, Clone)]
pub struct DnsFailed(pub String);
impl fmt::Display for DnsFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DnsFailed {}

/// Why a host could not be used.
#[derive(Debug, Clone)]
pub enum ResolveError {
    Dns(String),
    Ssrf(String),
}

/// Resolve `host` and vet **every** address. Any blocked address rejects the whole name (N5.1).
pub async fn resolve_checked(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, ResolveError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // IP literals: no DNS; explicit-rule metadata access is decided by the caller.
        permitted(ip, allow_private, false).map_err(ResolveError::Ssrf)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| ResolveError::Dns(format!("{host} did not resolve: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(ResolveError::Dns(format!("{host} did not resolve")));
    }
    for a in &addrs {
        permitted(a.ip(), allow_private, false)
            .map_err(|why| ResolveError::Ssrf(format!("{host} resolves to {why}")))?;
    }
    Ok(addrs)
}

/// The reqwest resolver: reqwest connects only to the vetted addresses returned here, so each
/// connection uses exactly one checked resolution (pinning; defeats DNS rebinding).
#[derive(Debug, Clone)]
pub struct PinningResolver {
    pub allow_private: bool,
    /// Operator proxy host: trusted infrastructure, exempt from SSRF checks (ADR-C2-4).
    pub proxy_host: Option<String>,
}

impl Resolve for PinningResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().trim_end_matches('.').to_ascii_lowercase();
        let allow_private = self.allow_private;
        let exempt = self
            .proxy_host
            .as_deref()
            .is_some_and(|p| p.eq_ignore_ascii_case(&host));
        Box::pin(async move {
            if exempt {
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .map_err(|e| {
                        Box::new(DnsFailed(format!("proxy {host} did not resolve: {e}")))
                            as Box<dyn std::error::Error + Send + Sync>
                    })?
                    .collect();
                return Ok(Box::new(addrs.into_iter()) as Addrs);
            }
            match resolve_checked(&host, 0, allow_private).await {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as Addrs),
                Err(ResolveError::Ssrf(m)) => {
                    Err(Box::new(SsrfBlocked(m)) as Box<dyn std::error::Error + Send + Sync>)
                }
                Err(ResolveError::Dns(m)) => {
                    Err(Box::new(DnsFailed(m)) as Box<dyn std::error::Error + Send + Sync>)
                }
            }
        })
    }
}
