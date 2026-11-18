//! Performance smoke check (U6 Q4): generous bounds (2× NFR-3) so shared CI runners don't flake.
//! Run with: cargo test --release -p sandboxd-runtime --test perf -- --ignored --nocapture

use std::sync::Arc;

use sandboxd_policy::Policy;
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;

#[test]
#[ignore = "release-mode performance smoke; run explicitly in CI"]
fn perf_smoke_within_twice_nfr3() {
    let rt = tokio::runtime::Runtime::new().expect("rt");
    rt.block_on(async {
        let cfg = RuntimeConfig {
            vfs: VfsConfig::under(std::env::temp_dir().join("sandboxd-perf")),
            ..RuntimeConfig::default()
        };
        let (sb, warm) = Sandbox::new(cfg, Arc::new(sandboxd_audit::NullSink))
            .await
            .expect("sandbox");
        eprintln!("warm-up: {warm:?}");
        let pol = Arc::new(Policy::builtin_default());
        let cases = [
            ("python print(1)", Language::Python, "print(1)", 600u64),
            (
                "python import json,csv,re,datetime",
                Language::Python,
                "import json, csv, re, datetime\nprint(1)",
                600,
            ),
            (
                "javascript console.log",
                Language::JavaScript,
                "console.log(1)",
                100,
            ),
        ];
        eprintln!(
            "\n{:<40} {:>8} {:>8} {:>14}",
            "workload", "best ms", "bound", "fuel"
        );
        for (label, lang, code, bound) in cases {
            let mut best = u64::MAX;
            let mut fuel = 0;
            for _ in 0..5 {
                let r = sb
                    .execute(RunRequest::new(lang, code), pol.clone(), "perf", None)
                    .await;
                assert_eq!(r.outcome, Outcome::Ok, "{label}");
                if r.timings.total_ms < best {
                    best = r.timings.total_ms;
                    fuel = r.fuel_used;
                }
            }
            eprintln!("{label:<40} {best:>8} {bound:>8} {fuel:>14}");
            assert!(
                best <= bound,
                "{label}: {best} ms exceeds {bound} ms (2× NFR-3)"
            );
        }
    });
}
