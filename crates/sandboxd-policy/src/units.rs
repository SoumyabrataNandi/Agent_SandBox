//! Exact unit parsing (design rule R2; Q2 = all byte suffixes are binary).

use std::{fmt, time::Duration};

/// A size in bytes. `K/KB/KiB`, `M/MB/MiB`, `G/GB/GiB`, `T/TB/TiB` are all powers of 1024.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub const KIB: u64 = 1024;
    pub const MIB: u64 = 1024 * 1024;
    pub const GIB: u64 = 1024 * 1024 * 1024;

    /// Bytes as `u64`.
    pub fn bytes(self) -> u64 {
        self.0
    }
    /// `n` MiB.
    pub const fn mib(n: u64) -> Self {
        Self(n * Self::MIB)
    }
    /// `n` KiB.
    pub const fn kib(n: u64) -> Self {
        Self(n * Self::KIB)
    }
    /// `n` GiB.
    pub const fn gib(n: u64) -> Self {
        Self(n * Self::GIB)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [(u64, &str); 4] = [
            (1 << 40, "TiB"),
            (ByteSize::GIB, "GiB"),
            (ByteSize::MIB, "MiB"),
            (ByteSize::KIB, "KiB"),
        ];
        for (m, u) in UNITS {
            if self.0 >= m && self.0.is_multiple_of(m) {
                return write!(f, "{}{u}", self.0 / m);
            }
        }
        for (m, u) in UNITS {
            if self.0 >= m {
                return write!(f, "{:.2}{u}", self.0 as f64 / m as f64);
            }
        }
        write!(f, "{}B", self.0)
    }
}

/// Split `"1.5GiB"` into (`"1.5"`, `"gib"`).
fn split(s: &str) -> Result<(&str, String), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let idx = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '_'))
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(idx);
    if num.is_empty() {
        return Err(format!("{s:?} does not start with a number"));
    }
    Ok((num, unit.trim().to_ascii_lowercase()))
}

/// Parse a non-negative decimal (`"1.5"`, `"1_000"`) scaled by `mult`, exactly, with overflow checks.
fn scaled(num: &str, mult: u128, original: &str) -> Result<u64, String> {
    let clean: String = num.chars().filter(|&c| c != '_').collect();
    let (int, frac) = match clean.split_once('.') {
        Some((i, f)) => (i, f),
        None => (clean.as_str(), ""),
    };
    if (int.is_empty() && frac.is_empty()) || clean.matches('.').count() > 1 {
        return Err(format!("{original:?} is not a valid number"));
    }
    if frac.len() > 9 {
        return Err(format!("{original:?} has too many decimal places (max 9)"));
    }
    let int_v: u128 = if int.is_empty() {
        0
    } else {
        int.parse()
            .map_err(|_| format!("{original:?} is not a valid number"))?
    };
    let frac_v: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse()
            .map_err(|_| format!("{original:?} is not a valid number"))?
    };
    let denom = 10u128.pow(frac.len() as u32);
    let total = int_v
        .checked_mul(mult)
        .and_then(|a| a.checked_add(frac_v * mult / denom))
        .ok_or_else(|| format!("{original:?} is too large"))?;
    if !(frac_v * mult).is_multiple_of(denom) {
        return Err(format!("{original:?} does not resolve to a whole number"));
    }
    u64::try_from(total).map_err(|_| format!("{original:?} is too large"))
}

/// Parse a byte size: `"128mb"`, `"256MiB"`, `"1.5G"`, `"4096"` (bytes).
pub fn parse_bytes(s: &str) -> Result<ByteSize, String> {
    let (num, unit) = split(s)?;
    let mult: u128 = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        other => {
            return Err(format!(
                "unknown size unit {other:?} in {s:?} (use B, KiB, MiB, GiB, TiB; KB/MB/GB mean the same)"
            ));
        }
    };
    scaled(num, mult, s).map(ByteSize)
}

/// Parse a duration: `"500ms"`, `"2s"`, `"1.5s"`, `"5m"`, `"1h"`. A unit is required.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let (num, unit) = split(s)?;
    let nanos_per: u128 = match unit.as_str() {
        "ms" => 1_000_000,
        "s" | "sec" | "secs" => 1_000_000_000,
        "m" | "min" | "mins" => 60_000_000_000,
        "h" | "hr" | "hrs" => 3_600_000_000_000,
        "" => return Err(format!("{s:?} needs a unit (ms, s, m or h)")),
        other => {
            return Err(format!(
                "unknown duration unit {other:?} in {s:?} (use ms, s, m, h)"
            ));
        }
    };
    scaled(num, nanos_per, s).map(Duration::from_nanos)
}

/// Parse a fuel budget: `"2G"`, `"500M"`, `"1_000_000"`. Suffixes are ×1000 (counts, not bytes).
pub fn parse_fuel(s: &str) -> Result<u64, String> {
    let (num, unit) = split(s)?;
    let mult: u128 = match unit.as_str() {
        "" => 1,
        "k" => 1_000,
        "m" => 1_000_000,
        "g" => 1_000_000_000,
        "t" => 1_000_000_000_000,
        other => {
            return Err(format!(
                "unknown fuel unit {other:?} in {s:?} (use K, M, G, T)"
            ));
        }
    };
    scaled(num, mult, s)
}

/// Human form of a duration for `explain` and error messages.
pub fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms.is_multiple_of(3_600_000) && ms > 0 {
        format!("{}h", ms / 3_600_000)
    } else if ms.is_multiple_of(60_000) && ms > 0 {
        format!("{}m", ms / 60_000)
    } else if ms.is_multiple_of(1000) {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

/// Human form of a fuel amount.
pub fn fmt_fuel(f: u64) -> String {
    for (m, u) in [
        (1_000_000_000_000, "T"),
        (1_000_000_000, "G"),
        (1_000_000, "M"),
        (1_000, "K"),
    ] {
        if f >= m && f.is_multiple_of(m) {
            return format!("{}{u}", f / m);
        }
    }
    f.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes() {
        assert_eq!(parse_bytes("128mb"), Ok(ByteSize::mib(128)));
        assert_eq!(parse_bytes("128MiB"), Ok(ByteSize::mib(128)));
        assert_eq!(parse_bytes("128 M"), Ok(ByteSize::mib(128)));
        assert_eq!(parse_bytes("1.5GiB"), Ok(ByteSize(3 * ByteSize::GIB / 2)));
        assert_eq!(parse_bytes("4096"), Ok(ByteSize(4096)));
        assert_eq!(parse_bytes("1_024b"), Ok(ByteSize(1024)));
        assert!(parse_bytes("12xb").is_err());
        assert!(parse_bytes("mb").is_err());
        assert!(parse_bytes("-1mb").is_err());
        assert!(parse_bytes("1.2.3mb").is_err());
        assert!(parse_bytes("0.0000000001b").is_err());
        assert!(parse_bytes("99999999999TiB").is_err());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("500ms"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("1.5s"), Ok(Duration::from_millis(1500)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert!(parse_duration("2").is_err());
        assert!(parse_duration("2d").is_err());
    }

    #[test]
    fn fuel() {
        assert_eq!(parse_fuel("2G"), Ok(2_000_000_000));
        assert_eq!(parse_fuel("2g"), Ok(2_000_000_000));
        assert_eq!(parse_fuel("1.5M"), Ok(1_500_000));
        assert_eq!(parse_fuel("1_000"), Ok(1000));
        assert!(parse_fuel("2GiB").is_err());
    }

    #[test]
    fn display_roundtrip() {
        for s in ["128MiB", "1GiB", "256KiB", "17B"] {
            assert_eq!(parse_bytes(s).map(|b| b.to_string()).as_deref(), Ok(s));
        }
        assert_eq!(fmt_duration(Duration::from_millis(1500)), "1500ms");
        assert_eq!(fmt_duration(Duration::from_secs(120)), "2m");
        assert_eq!(fmt_fuel(2_000_000_000), "2G");
    }
}
