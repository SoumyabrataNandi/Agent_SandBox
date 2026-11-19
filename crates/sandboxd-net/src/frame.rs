//! Device wire codec (ADR-C2-2): `u32 LE header_len` · JSON header · raw body.

use serde::{Deserialize, Serialize};

/// Max header JSON size (Q5).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Max request headers (Q5).
pub const MAX_HEADERS: usize = 100;
/// Max size of one header value (Q5).
pub const MAX_HEADER_VALUE: usize = 8 * 1024;

/// Request header written by the guest shim.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeader {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body_len: u64,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Machine-readable failure (C2-U2 design H7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameError {
    pub code: String,
    pub message: String,
}

/// Response header read by the guest shim. `status == 0` ⇔ `error` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseHeader {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub url: String,
    pub redirects: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<FrameError>,
}

impl ResponseHeader {
    /// An error frame.
    pub fn error(code: &str, message: impl Into<String>, url: &str, redirects: u32) -> Self {
        Self {
            status: 0,
            headers: Vec::new(),
            url: url.into(),
            redirects,
            error: Some(FrameError {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

/// Outcome of decoding a (possibly partial) request buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// More bytes are needed.
    Incomplete,
    /// A full request; any trailing bytes are an error.
    Complete(RequestHeader, Vec<u8>),
}

/// Decode a request frame. `max_body` is the policy's `max_request_bytes`.
pub fn decode_request(buf: &[u8], max_body: u64) -> Result<Decoded, String> {
    if buf.len() < 4 {
        return Ok(Decoded::Incomplete);
    }
    let hlen = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if hlen == 0 || hlen > MAX_HEADER_BYTES {
        return Err(format!(
            "request header must be 1..={MAX_HEADER_BYTES} bytes"
        ));
    }
    if buf.len() < 4 + hlen {
        return Ok(Decoded::Incomplete);
    }
    let h: RequestHeader = serde_json::from_slice(&buf[4..4 + hlen])
        .map_err(|e| format!("bad request header: {e}"))?;
    if h.body_len > max_body {
        return Err(format!(
            "request body of {} bytes exceeds the policy limit of {max_body}",
            h.body_len
        ));
    }
    if h.headers.len() > MAX_HEADERS {
        return Err(format!("at most {MAX_HEADERS} request headers"));
    }
    let body_len = usize::try_from(h.body_len).map_err(|_| "body too large")?;
    let total = 4 + hlen + body_len;
    match buf.len().cmp(&total) {
        std::cmp::Ordering::Less => Ok(Decoded::Incomplete),
        std::cmp::Ordering::Greater => Err("trailing bytes after the request frame".into()),
        std::cmp::Ordering::Equal => Ok(Decoded::Complete(h, buf[4 + hlen..].to_vec())),
    }
}

/// Encode a response frame.
pub fn encode_response(h: &ResponseHeader, body: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(h).unwrap_or_else(|_| b"{\"status\":0,\"headers\":[],\"url\":\"\",\"redirects\":0,\"error\":{\"code\":\"PROTOCOL\",\"message\":\"encode\"}}".to_vec());
    let mut out = Vec::with_capacity(4 + json.len() + body.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(body);
    out
}

/// Encode a request frame (used by tests and by the Rust side of guest-shim tests).
pub fn encode_request(h: &RequestHeader, body: &[u8]) -> Vec<u8> {
    let json = serde_json::to_vec(h).unwrap_or_default();
    let mut out = Vec::with_capacity(4 + json.len() + body.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(&json);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(body: &[u8]) -> RequestHeader {
        RequestHeader {
            method: "POST".into(),
            url: "https://a.example/x".into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body_len: body.len() as u64,
            timeout_ms: None,
        }
    }

    #[test]
    fn roundtrip_and_partial() {
        let body = b"hello";
        let frame = encode_request(&req(body), body);
        for cut in 0..frame.len() {
            assert_eq!(
                decode_request(&frame[..cut], 1024),
                Ok(Decoded::Incomplete),
                "cut {cut}"
            );
        }
        assert_eq!(
            decode_request(&frame, 1024),
            Ok(Decoded::Complete(req(body), body.to_vec()))
        );
        let mut extra = frame.clone();
        extra.push(0);
        assert!(decode_request(&extra, 1024).is_err());
        assert!(decode_request(&frame, 2).is_err(), "body over policy limit");
    }

    #[test]
    fn rejects_bad_headers() {
        assert!(decode_request(&[0, 0, 0, 0], 10).is_err());
        assert!(decode_request(&(MAX_HEADER_BYTES as u32 + 1).to_le_bytes(), 10).is_err());
        let mut f = 5u32.to_le_bytes().to_vec();
        f.extend_from_slice(b"nope!");
        assert!(decode_request(&f, 10).is_err());
        let unknown = br#"{"method":"GET","url":"x","smuggle":1}"#;
        let mut f = (unknown.len() as u32).to_le_bytes().to_vec();
        f.extend_from_slice(unknown);
        assert!(decode_request(&f, 10).is_err(), "unknown fields rejected");
    }

    #[test]
    fn response_roundtrip() {
        let h = ResponseHeader::error("DENIED", "no rule", "https://x/", 0);
        let f = encode_response(&h, b"");
        let hlen = u32::from_le_bytes([f[0], f[1], f[2], f[3]]) as usize;
        let back: ResponseHeader = serde_json::from_slice(&f[4..4 + hlen]).expect("json");
        assert_eq!(back, h);
    }

    proptest::proptest! {
        #[test]
        fn decoder_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let _ = decode_request(&bytes, 100);
        }
    }
}
