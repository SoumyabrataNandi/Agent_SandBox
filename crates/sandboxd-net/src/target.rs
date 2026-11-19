//! Target URL canonicalization (design §2, rules U1–U6) and allowlist matching (§3).

use std::net::IpAddr;

use sandboxd_policy::{HttpRule, Scheme, TcpRule};
use url::{Host, Url};

/// A canonical, validated HTTP target.
#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    pub scheme: Scheme,
    /// Canonical host text: lower-case domain (punycode) or IP without brackets.
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    /// Canonical path (dot segments removed by the WHATWG parser).
    pub path: String,
}

impl Target {
    /// `scheme://host:port`, used to decide cross-origin redirects.
    pub fn origin(&self) -> (Scheme, String, u16) {
        (self.scheme, self.host.clone(), self.port)
    }

    /// Path for audit: the query string is never logged, only its size.
    pub fn audit_path(&self) -> String {
        match self.url.query() {
            Some(q) if !q.is_empty() => format!("{}?…[{} params]", self.path, q.split('&').count()),
            _ => self.path.clone(),
        }
    }
}

/// Parse and validate a URL from the guest (rules U1–U4).
pub fn parse_target(raw: &str) -> Result<Target, String> {
    if raw.len() > 8192 {
        return Err("URL longer than 8192 bytes".into());
    }
    if raw.contains('\\') {
        return Err("backslashes are not allowed in URLs".into()); // U4
    }
    let mut url = Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    let scheme = match url.scheme() {
        "https" => Scheme::Https,
        "http" => Scheme::Http,
        other => {
            return Err(format!(
                "scheme {other:?} is not supported (use http or https)"
            ));
        } // U1
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err("credentials in URLs are not allowed".into()); // U2
    }
    url.set_fragment(None); // U3
    let (host, ip) = match url.host() {
        Some(Host::Domain(d)) => (d.trim_end_matches('.').to_ascii_lowercase(), None),
        Some(Host::Ipv4(v4)) => (v4.to_string(), Some(IpAddr::V4(v4))),
        Some(Host::Ipv6(v6)) => (v6.to_string(), Some(IpAddr::V6(v6))),
        None => return Err("URL has no host".into()),
    };
    if host.is_empty() {
        return Err("URL has no host".into());
    }
    let port = url.port_or_known_default().ok_or("URL has no port")?;
    let path = url.path().to_string();
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Err("encoded path separators (%2F, %5C) are not allowed".into()); // U4 / Q3
    }
    Ok(Target {
        url,
        scheme,
        host,
        ip,
        port,
        path,
    })
}

fn host_matches(rule_host: &str, host: &str, ip: Option<IpAddr>) -> bool {
    match (rule_host.parse::<IpAddr>(), ip) {
        (Ok(r), Some(t)) => r == t,
        (Ok(_), None) | (Err(_), Some(_)) => false, // IP rules match IP literals only, and vice versa
        (Err(_), None) => rule_host.eq_ignore_ascii_case(host),
    }
}

/// Segment-aware prefix match (rule U5).
pub fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    }
}

/// First HTTP rule allowing `method` on `t`, or the most specific reason why none does.
pub fn match_http<'a>(
    rules: &'a [HttpRule],
    t: &Target,
    method: &str,
) -> Result<&'a HttpRule, String> {
    let same_origin: Vec<&HttpRule> = rules
        .iter()
        .filter(|r| {
            r.scheme == t.scheme && r.port == t.port && host_matches(&r.host, &t.host, t.ip)
        })
        .collect();
    if same_origin.is_empty() {
        let other_scheme = rules
            .iter()
            .any(|r| r.port == t.port && host_matches(&r.host, &t.host, t.ip));
        return Err(if other_scheme {
            format!(
                "scheme {} is not allowed for {}:{}",
                t.scheme.as_str(),
                t.host,
                t.port
            )
        } else {
            format!(
                "no rule allows {}://{}:{}",
                t.scheme.as_str(),
                t.host,
                t.port
            )
        });
    }
    let by_method: Vec<&&HttpRule> = same_origin
        .iter()
        .filter(|r| r.methods.iter().any(|m| m == method))
        .collect();
    if by_method.is_empty() {
        return Err(format!(
            "method {method} is not allowed for {}://{}:{}",
            t.scheme.as_str(),
            t.host,
            t.port
        ));
    }
    by_method
        .into_iter()
        .find(|r| prefix_matches(&r.path_prefix, &t.path))
        .copied()
        .ok_or_else(|| {
            format!(
                "path {} is outside the allowed prefixes for {}",
                t.path, t.host
            )
        })
}

/// `true` if `ip` is named literally by some HTTP rule for this target (FR-N5.4).
pub fn explicit_ip_rule(rules: &[HttpRule], ip: IpAddr) -> bool {
    rules
        .iter()
        .any(|r| r.host.parse::<IpAddr>().is_ok_and(|r| r == ip))
}

/// Parse `host:port` / `[v6]:port` from a device path and match a TCP rule.
pub fn match_tcp<'a>(
    rules: &'a [TcpRule],
    spec: &str,
) -> Result<(&'a TcpRule, String, Option<IpAddr>, u16), String> {
    let (host, port) = if let Some(rest) = spec.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or("expected [ipv6]:port")?;
        (h.to_string(), p)
    } else {
        let (h, p) = spec.rsplit_once(':').ok_or("expected host:port")?;
        (h.to_ascii_lowercase(), p)
    };
    let port: u16 = port.parse().map_err(|_| format!("invalid port {port:?}"))?;
    if host.is_empty() || port == 0 {
        return Err("invalid host or port".into());
    }
    let ip = host.parse::<IpAddr>().ok();
    let host = ip.map(|i| i.to_string()).unwrap_or(host);
    rules
        .iter()
        .find(|r| r.port == port && host_matches(&r.host, &host, ip))
        .map(|r| (r, host.clone(), ip, port))
        .ok_or_else(|| format!("no rule allows tcp://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(scheme: Scheme, host: &str, port: u16, methods: &[&str], prefix: &str) -> HttpRule {
        HttpRule {
            scheme,
            host: host.into(),
            port,
            methods: methods.iter().map(|m| m.to_string()).collect(),
            path_prefix: prefix.into(),
        }
    }

    #[test]
    fn canonicalization_defeats_ip_tricks() {
        for (raw, host) in [
            ("http://2130706433/", "127.0.0.1"),
            ("http://0x7f.1/", "127.0.0.1"),
            ("http://0177.0.0.1/", "127.0.0.1"),
            ("http://127.1/", "127.0.0.1"),
            ("http://[::ffff:127.0.0.1]/", "::ffff:127.0.0.1"),
            ("http://[::ffff:7f00:1]/", "::ffff:127.0.0.1"),
            ("https://API.Example.COM./x", "api.example.com"),
        ] {
            let t = parse_target(raw).expect(raw);
            assert_eq!(t.host, host, "{raw}");
        }
        assert_eq!(
            parse_target("https://a.example/v1/../admin")
                .expect("ok")
                .path,
            "/admin"
        );
        assert_eq!(
            parse_target("https://a.example/v1/%2e%2e/admin")
                .expect("ok")
                .path,
            "/admin"
        );
        // WHATWG: extra slashes after a special scheme are skipped, so this targets host "nohost",
        // which must still pass the allowlist like any other host.
        assert_eq!(parse_target("https:///nohost").expect("ok").host, "nohost");
    }

    #[test]
    fn rejected_urls() {
        for bad in [
            "ftp://a.example/",
            "file:///etc/passwd",
            "https://user:pw@a.example/",
            "https://a.example/v1%2Fadmin",
            "https://a.example/v1%5cadmin",
            "https://a.example\\@evil/",
            "https://",
            "http://:80/",
            "gopher://a.example/",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn audit_path_redacts_query() {
        let t = parse_target("https://a.example/s?q=secret&key=abc#frag").expect("ok");
        assert_eq!(t.audit_path(), "/s?…[2 params]");
        assert!(t.url.fragment().is_none());
    }

    #[test]
    fn matching() {
        let rules = vec![
            rule(
                Scheme::Https,
                "api.example.com",
                443,
                &["GET", "POST"],
                "/v1",
            ),
            rule(Scheme::Http, "plain.example.com", 80, &["GET"], "/"),
            rule(Scheme::Https, "10.0.0.5", 8443, &["GET"], "/"),
        ];
        let m = |u: &str, meth: &str| match_http(&rules, &parse_target(u).expect(u), meth);
        assert!(m("https://api.example.com/v1", "GET").is_ok());
        assert!(m("https://api.example.com/v1/x?y=1", "POST").is_ok());
        assert!(m("https://API.example.com/v1/x", "GET").is_ok());
        assert!(
            m("https://api.example.com/v1admin", "GET")
                .expect_err("must be denied")
                .contains("outside")
        );
        assert!(m("https://api.example.com/v2", "GET").is_err());
        assert!(
            m("https://api.example.com/v1", "DELETE")
                .expect_err("must be denied")
                .contains("method")
        );
        assert!(
            m("https://api.example.com:8443/v1", "GET")
                .expect_err("must be denied")
                .contains("no rule")
        );
        assert!(
            m("http://api.example.com:443/v1", "GET")
                .expect_err("must be denied")
                .contains("scheme")
        );
        assert!(m("http://plain.example.com/anything", "GET").is_ok());
        assert!(m("https://plain.example.com/", "GET").is_err());
        assert!(m("https://10.0.0.5:8443/", "GET").is_ok());
        assert!(m("https://evil.example/", "GET").is_err());
        assert!(m("https://api.example.com.evil.example/v1", "GET").is_err());
        assert!(explicit_ip_rule(&rules, "10.0.0.5".parse().expect("ip")));
        assert!(!explicit_ip_rule(&rules, "10.0.0.6".parse().expect("ip")));
    }

    #[test]
    fn prefix_is_segment_aware() {
        assert!(prefix_matches("/v1", "/v1"));
        assert!(prefix_matches("/v1", "/v1/x"));
        assert!(!prefix_matches("/v1", "/v1admin"));
        assert!(prefix_matches("/v1/", "/v1/x"));
        assert!(!prefix_matches("/v1/", "/v1"));
        assert!(prefix_matches("/", "/anything"));
    }

    #[test]
    fn tcp_specs() {
        let rules = vec![
            TcpRule {
                host: "db.internal".into(),
                port: 5432,
            },
            TcpRule {
                host: "::1".into(),
                port: 7,
            },
        ];
        assert!(match_tcp(&rules, "db.internal:5432").is_ok());
        assert!(match_tcp(&rules, "DB.internal:5432").is_ok());
        assert!(match_tcp(&rules, "db.internal:5433").is_err());
        assert!(match_tcp(&rules, "[::1]:7").is_ok());
        assert!(match_tcp(&rules, "db.internal").is_err());
        assert!(match_tcp(&rules, "db.internal:0").is_err());
    }

    proptest::proptest! {
        #[test]
        fn parser_never_panics(s in "\\PC{0,80}") {
            let _ = parse_target(&s);
            let _ = match_tcp(&[], &s);
        }

        #[test]
        fn traversal_never_escapes_prefix(segs in proptest::collection::vec("(\\.\\.|\\.|%2e%2e|[a-z]{1,3})", 0..8)) {
            let raw = format!("https://api.example.com/v1/{}", segs.join("/"));
            if let Ok(t) = parse_target(&raw) {
                let rules = vec![rule(Scheme::Https, "api.example.com", 443, &["GET"], "/v1/")];
                if match_http(&rules, &t, "GET").is_ok() {
                    proptest::prop_assert!(t.path.starts_with("/v1/"), "{raw} -> {}", t.path);
                }
            }
        }
    }
}
