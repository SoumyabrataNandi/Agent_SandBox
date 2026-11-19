//! `/dev/sandbox/http`: one request/response exchange per fd (design §5, H1–H7).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sandboxd_audit::{Decision, EventKind};
use sandboxd_policy::Scheme;
use sandboxd_vfs::{DeviceFuture, VirtualDevice};
use wasmtime_wasi::p1::types::Errno;

use crate::{
    RunInner,
    frame::{self, Decoded, MAX_HEADER_BYTES, MAX_HEADER_VALUE, ResponseHeader},
    ip::permitted,
    resolve::{DnsFailed, ResolveError, SsrfBlocked, resolve_checked},
    target::{Target, match_http, parse_target},
};

const MAX_REDIRECTS: u32 = 5;
/// Request headers the broker owns (H2).
const DROP_REQUEST: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
];
/// Hop-by-hop response headers not returned to the guest (Q2).
const DROP_RESPONSE: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-connection",
];
/// Dropped when a redirect changes origin (Q4).
const CROSS_ORIGIN_DROP: &[&str] = &["authorization", "cookie", "proxy-authorization"];

enum State {
    Writing(Vec<u8>),
    Done(Vec<u8>, usize),
}

pub(crate) struct HttpDevice {
    run: Arc<RunInner>,
    state: State,
}

impl HttpDevice {
    pub(crate) fn new(run: Arc<RunInner>) -> Self {
        Self {
            run,
            state: State::Writing(Vec::new()),
        }
    }

    fn max_frame(&self) -> usize {
        4 + MAX_HEADER_BYTES
            + usize::try_from(self.run.net.max_request_bytes.bytes()).unwrap_or(usize::MAX)
    }
}

impl VirtualDevice for HttpDevice {
    fn write<'a>(&'a mut self, data: &'a [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            let max = self.max_frame();
            match &mut self.state {
                State::Writing(buf) => {
                    if buf.len() + data.len() > max {
                        return Err(Errno::Msgsize);
                    }
                    buf.extend_from_slice(data);
                    Ok(data.len())
                }
                State::Done(..) => Err(Errno::Badf),
            }
        })
    }

    fn read<'a>(&'a mut self, out: &'a mut [u8]) -> DeviceFuture<'a, usize> {
        Box::pin(async move {
            if let State::Writing(buf) = &self.state {
                let frame = match frame::decode_request(buf, self.run.net.max_request_bytes.bytes())
                {
                    Ok(Decoded::Incomplete) => return Err(Errno::Inval),
                    Ok(Decoded::Complete(h, body)) => exchange(&self.run, h, body).await,
                    Err(msg) => {
                        let h = ResponseHeader::error("PROTOCOL", msg, "", 0);
                        frame::encode_response(&h, b"")
                    }
                };
                self.state = State::Done(frame, 0);
            }
            match &mut self.state {
                State::Done(frame, off) => {
                    let n = (frame.len() - *off).min(out.len());
                    out[..n].copy_from_slice(&frame[*off..*off + n]);
                    *off += n;
                    Ok(n)
                }
                State::Writing(_) => Err(Errno::Inval),
            }
        })
    }

    fn close(&mut self) -> DeviceFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

struct Hop<'a> {
    run: &'a RunInner,
    target: &'a Target,
    method: &'a str,
    hop: u32,
    started: Instant,
}

impl Hop<'_> {
    fn audit(
        &self,
        ip: Option<String>,
        status: Option<u16>,
        out: u64,
        inn: u64,
        decision: Decision,
        reason: Option<String>,
    ) {
        self.run.emit(EventKind::NetRequest {
            proto: "http".into(),
            scheme: Some(self.target.scheme.as_str().into()),
            host: self.target.host.clone(),
            ip,
            port: self.target.port,
            method: Some(self.method.into()),
            path: Some(self.target.audit_path()),
            status,
            hop: self.hop,
            bytes_out: out,
            bytes_in: inn,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            decision,
            reason,
        });
    }

    fn deny(&self, code: &str, reason: String, url: &str) -> Vec<u8> {
        self.audit(
            self.target.ip.map(|i| i.to_string()),
            None,
            0,
            0,
            Decision::Deny,
            Some(reason.clone()),
        );
        frame::encode_response(&ResponseHeader::error(code, reason, url, self.hop), b"")
    }
}

/// Build the request header map (H2). Returns the reason on invalid input.
fn request_headers(raw: &[(String, String)]) -> Result<HeaderMap, String> {
    let connection_listed: Vec<String> = raw
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut map = HeaderMap::new();
    for (k, v) in raw {
        if v.len() > MAX_HEADER_VALUE {
            return Err(format!(
                "header {k} is longer than {MAX_HEADER_VALUE} bytes"
            ));
        }
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|_| format!("invalid header name {k:?}"))?;
        let lname = name.as_str();
        if DROP_REQUEST.contains(&lname)
            || lname.starts_with("proxy-")
            || connection_listed.iter().any(|c| c == lname)
        {
            continue;
        }
        if v.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(format!("header {k} contains CR, LF or NUL"));
        }
        let value =
            HeaderValue::from_str(v).map_err(|_| format!("invalid value for header {k}"))?;
        map.append(name, value);
    }
    Ok(map)
}

fn response_headers(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter(|(k, _)| !DROP_RESPONSE.contains(&k.as_str()))
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// Map a reqwest failure to a frame error code (H7). Messages never include the URL/query.
fn classify_error(e: reqwest::Error) -> (&'static str, String) {
    let e = e.without_url();
    // Walk the cause chain. `std::io::Error::source()` skips the error it wraps, so also look
    // inside `io::Error::get_ref()` (hyper-rustls reports TLS failures as io::Error(rustls::Error)).
    let mut innermost = String::new();
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&e);
    while let Some(s) = src {
        let wrapped = s
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .map(|w| w as &(dyn std::error::Error + 'static));
        for cand in std::iter::once(s).chain(wrapped) {
            if let Some(b) = cand.downcast_ref::<SsrfBlocked>() {
                return ("SSRF", b.0.clone());
            }
            if let Some(d) = cand.downcast_ref::<DnsFailed>() {
                return ("DNS", d.0.clone());
            }
            if let Some(t) = cand.downcast_ref::<rustls::Error>() {
                return ("TLS", format!("TLS failure: {t}"));
            }
        }
        innermost = s.to_string();
        src = s.source().or(wrapped);
    }
    let detail = if innermost.is_empty() {
        e.to_string()
    } else {
        format!("{e}: {innermost}")
    };
    if e.is_timeout() {
        ("TIMEOUT", "the request timed out".into())
    } else if e.is_connect() {
        ("CONNECT", format!("connection failed: {detail}"))
    } else {
        ("CONNECT", format!("request failed: {detail}"))
    }
}

/// Run one exchange including broker-managed redirects. Always returns a response frame.
async fn exchange(run: &RunInner, h: frame::RequestHeader, body: Vec<u8>) -> Vec<u8> {
    let started = Instant::now();
    let mut cap = run.net.request_timeout;
    if let Some(ms) = h.timeout_ms {
        cap = cap.min(Duration::from_millis(ms));
    }
    let deadline = Instant::now() + run.budget(cap);
    let mut method = h.method.to_ascii_uppercase();
    let mut body = body;
    let mut headers = match request_headers(&h.headers) {
        Ok(m) => m,
        Err(reason) => {
            return frame::encode_response(
                &ResponseHeader::error("PROTOCOL", reason, &h.url, 0),
                b"",
            );
        }
    };
    let mut target = match parse_target(&h.url) {
        Ok(t) => t,
        Err(reason) => {
            run.emit(EventKind::NetRequest {
                proto: "http".into(),
                scheme: None,
                host: "<invalid>".into(),
                ip: None,
                port: 0,
                method: Some(method.clone()),
                path: None,
                status: None,
                hop: 0,
                bytes_out: 0,
                bytes_in: 0,
                duration_ms: 0,
                decision: Decision::Deny,
                reason: Some(reason.clone()),
            });
            return frame::encode_response(&ResponseHeader::error("DENIED", reason, "", 0), b"");
        }
    };
    let Some(client) = run.client.as_ref() else {
        return frame::encode_response(
            &ResponseHeader::error("NETWORK_DISABLED", "HTTP egress is not granted", &h.url, 0),
            b"",
        );
    };

    for hop_no in 0..=MAX_REDIRECTS {
        let hop = Hop {
            run,
            target: &target,
            method: &method,
            hop: hop_no,
            started: Instant::now(),
        };
        let url_s = target.url.to_string();

        // Allowlist (§3).
        if let Err(reason) = match_http(&run.net.http, &target, &method) {
            return hop.deny("DENIED", reason, &url_s);
        }
        // SSRF for IP literals (the resolver handles names) and pre-check behind a proxy (§4).
        if let Some(ip) = target.ip {
            if let Err(why) = permitted(ip, run.net.allow_private_ips, run.explicit_ip_rule(ip)) {
                return hop.deny("SSRF", why, &url_s);
            }
        } else if run.proxy_active {
            match resolve_checked(&target.host, target.port, run.net.allow_private_ips).await {
                Ok(_) => {}
                Err(ResolveError::Ssrf(m)) => return hop.deny("SSRF", m, &url_s),
                Err(ResolveError::Dns(m)) => return hop.deny("DNS", m, &url_s),
            }
        }
        // Quotas (H3).
        if !run.take_request() {
            return hop.deny(
                "QUOTA",
                format!("network request quota ({}) exhausted", run.net.max_requests),
                &url_s,
            );
        }
        if !run.add_out(body.len() as u64) {
            return hop.deny("QUOTA", "network byte quota exhausted".into(), &url_s);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            run.mark_limit();
            return hop.deny("TIMEOUT", "the request timed out".into(), &url_s);
        }
        let Ok(m) = reqwest::Method::from_bytes(method.as_bytes()) else {
            return hop.deny("PROTOCOL", format!("invalid method {method:?}"), &url_s);
        };
        let req = client
            .request(m, target.url.clone())
            .headers(headers.clone())
            .body(body.clone())
            .timeout(remaining);

        let resp = match tokio::time::timeout(remaining, req.send()).await {
            Err(_) => {
                run.mark_limit();
                return hop.deny("TIMEOUT", "the request timed out".into(), &url_s);
            }
            Ok(Err(e)) => {
                let (code, msg) = classify_error(e);
                if code == "TIMEOUT" {
                    run.mark_limit();
                }
                return hop.deny(code, msg, &url_s);
            }
            Ok(Ok(r)) => r,
        };
        let status = resp.status().as_u16();
        let peer = resp.remote_addr().map(|a| a.ip().to_string());
        let resp_headers = response_headers(resp.headers());
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Body with caps (H5).
        let max_resp = run.net.max_response_bytes.bytes();
        let mut data: Vec<u8> = Vec::new();
        let mut resp = resp;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let chunk = match tokio::time::timeout(left, resp.chunk()).await {
                Err(_) => {
                    run.mark_limit();
                    hop.audit(
                        peer.clone(),
                        Some(status),
                        body.len() as u64,
                        data.len() as u64,
                        Decision::Deny,
                        Some("timeout reading response".into()),
                    );
                    return frame::encode_response(
                        &ResponseHeader::error(
                            "TIMEOUT",
                            "timed out reading the response",
                            &url_s,
                            hop_no,
                        ),
                        b"",
                    );
                }
                Ok(Err(e)) => {
                    let (code, msg) = classify_error(e);
                    hop.audit(
                        peer.clone(),
                        Some(status),
                        body.len() as u64,
                        data.len() as u64,
                        Decision::Deny,
                        Some(msg.clone()),
                    );
                    return frame::encode_response(
                        &ResponseHeader::error(code, msg, &url_s, hop_no),
                        b"",
                    );
                }
                Ok(Ok(None)) => break,
                Ok(Ok(Some(c))) => c,
            };
            if data.len() as u64 + chunk.len() as u64 > max_resp {
                run.limit_hit(max_resp, data.len() as u64 + chunk.len() as u64);
                hop.audit(
                    peer.clone(),
                    Some(status),
                    body.len() as u64,
                    data.len() as u64,
                    Decision::Deny,
                    Some("response too large".into()),
                );
                return frame::encode_response(
                    &ResponseHeader::error(
                        "RESPONSE_TOO_LARGE",
                        format!("response exceeds {}", run.net.max_response_bytes),
                        &url_s,
                        hop_no,
                    ),
                    b"",
                );
            }
            if !run.add_in(chunk.len() as u64) {
                hop.audit(
                    peer.clone(),
                    Some(status),
                    body.len() as u64,
                    data.len() as u64,
                    Decision::Deny,
                    Some("byte quota".into()),
                );
                return frame::encode_response(
                    &ResponseHeader::error("QUOTA", "network byte quota exhausted", &url_s, hop_no),
                    b"",
                );
            }
            data.extend_from_slice(&chunk);
        }
        hop.audit(
            peer,
            Some(status),
            body.len() as u64,
            data.len() as u64,
            Decision::Allow,
            None,
        );

        // Redirects (H6).
        let is_redirect = matches!(status, 301 | 302 | 303 | 307 | 308);
        let Some(loc) = location.filter(|_| is_redirect) else {
            let header = ResponseHeader {
                status,
                headers: resp_headers,
                url: url_s,
                redirects: hop_no,
                error: None,
            };
            return frame::encode_response(&header, &data);
        };
        if hop_no == MAX_REDIRECTS {
            return frame::encode_response(
                &ResponseHeader::error(
                    "TOO_MANY_REDIRECTS",
                    format!("more than {MAX_REDIRECTS} redirects"),
                    &url_s,
                    hop_no,
                ),
                b"",
            );
        }
        let next_raw = match target.url.join(&loc) {
            Ok(u) => u.to_string(),
            Err(_) => {
                return frame::encode_response(
                    &ResponseHeader::error("PROTOCOL", "invalid redirect Location", &url_s, hop_no),
                    b"",
                );
            }
        };
        let next = match parse_target(&next_raw) {
            Ok(t) => t,
            Err(reason) => {
                return frame::encode_response(
                    &ResponseHeader::error(
                        "DENIED",
                        format!("redirect refused: {reason}"),
                        &url_s,
                        hop_no,
                    ),
                    b"",
                );
            }
        };
        if target.scheme == Scheme::Https && next.scheme == Scheme::Http {
            let refused = Hop {
                run,
                target: &next,
                method: &method,
                hop: hop_no + 1,
                started: Instant::now(),
            };
            return refused.deny(
                "DENIED",
                "redirect from https to http refused".into(),
                &next_raw,
            );
        }
        if matches!(status, 301..=303) && method != "HEAD" {
            method = "GET".into();
            body.clear();
            headers.remove(reqwest::header::CONTENT_TYPE);
        }
        if next.origin() != target.origin() {
            for h in CROSS_ORIGIN_DROP {
                headers.remove(*h);
            }
        }
        target = next;
    }
    let _ = started;
    frame::encode_response(
        &ResponseHeader::error(
            "TOO_MANY_REDIRECTS",
            "too many redirects",
            &h.url,
            MAX_REDIRECTS,
        ),
        b"",
    )
}
