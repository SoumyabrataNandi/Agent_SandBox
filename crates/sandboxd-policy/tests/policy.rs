use std::{path::PathBuf, time::Duration};

use proptest::prelude::*;
use sandboxd_policy::*;

/// A real directory to use as a mount source, with `/` separators so it embeds cleanly in TOML/YAML.
fn host_dir() -> String {
    let d = std::env::temp_dir().join("sandboxd-policy-tests-host");
    std::fs::create_dir_all(&d).expect("mkdir");
    d.display().to_string().replace('\\', "/")
}

fn golden(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    std::fs::read_to_string(p)
        .expect("golden")
        .replace("@HOST_DIR@", &host_dir())
}

fn toml(src: &str) -> Result<Policy, PolicyErrors> {
    Policy::from_toml(src, "t.toml")
}

fn err_text(src: &str) -> String {
    toml(src).expect_err("should be rejected").to_string()
}

const HEAD: &str = "version = 1\nname = \"t\"\n";

// ---- R11: TOML ↔ YAML parity (acceptance criterion 9) ----

#[test]
fn toml_and_yaml_goldens_are_identical() {
    for stem in ["minimal", "full"] {
        let t = Policy::from_toml(&golden(&format!("{stem}.toml")), "t").expect("toml valid");
        let y = Policy::from_yaml(&golden(&format!("{stem}.yaml")), "y").expect("yaml valid");
        assert_eq!(t.spec(), y.spec(), "parity failed for {stem}");
    }
}

#[test]
fn full_golden_resolves_values_exactly() {
    let p = Policy::from_toml(&golden("full.toml"), "t").expect("valid");
    let l = p.limits();
    assert_eq!(l.wall_clock, Duration::from_millis(1500));
    assert_eq!(l.fuel, 500_000_000);
    assert_eq!(l.memory, ByteSize::mib(128));
    assert_eq!(l.stdout, ByteSize::kib(64));
    assert_eq!(l.stderr, ByteSize(4096));
    assert_eq!(l.input_bytes, ByteSize::mib(8));
    assert_eq!(p.filesystem().inputs, "/input");
    assert_eq!(p.filesystem().mounts[0].mode, MountMode::ReadOnly);
    assert_eq!(p.network().http[0].host, "api.example.com");
    assert_eq!(p.network().http[0].methods, vec!["GET", "POST"]);
    assert!(p.audit().log_code);
    // Q3: valid shape, but grants egress → refused by this version.
    let e = p
        .ensure_supported()
        .expect_err("network must be unsupported");
    assert!(e.to_string().contains("network broker"));
}

#[test]
fn minimal_gets_defaults_and_is_supported() {
    let p = toml(HEAD).expect("valid");
    assert_eq!(p.limits(), &Limits::default());
    assert_eq!(p.filesystem().inputs, "/in");
    assert_eq!(p.filesystem().outputs, "/out");
    assert!(p.env().is_empty() && p.filesystem().mounts.is_empty());
    p.ensure_supported().expect("supported");
}

// ---- R1: unknown keys ----

#[test]
fn unknown_keys_rejected_at_any_depth() {
    for src in [
        format!("{HEAD}colour = 1"),
        format!("{HEAD}[limits]\ncpu = \"2s\""),
        format!("{HEAD}[[filesystem.mount]]\nguest=\"/a\"\nhost=\"/\"\nmode=\"ro\"\nextra=1"),
        format!("{HEAD}[network]\nhttp = [{{ host = \"a\", scheme = \"https\" }}]"),
    ] {
        assert!(toml(&src).is_err(), "{src}");
    }
    assert!(Policy::from_yaml("version: 1\nname: t\nlimit: {}\n", "y").is_err());
}

// ---- R2/R3: units and ranges ----

#[test]
fn ranges_enforced_with_clear_messages() {
    let e = err_text(&format!("{HEAD}[limits]\nmemory = \"8GiB\""));
    assert!(e.contains("limits.memory") && e.contains("4GiB"), "{e}");
    let e = err_text(&format!("{HEAD}[limits]\nwall_clock = \"2\""));
    assert!(e.contains("needs a unit"), "{e}");
    let e = err_text(&format!("{HEAD}[limits]\nwall_clock = \"2h\""));
    assert!(e.contains("limits.wall_clock"), "{e}");
    assert!(toml(&format!("{HEAD}[limits]\nfuel = 10")).is_err());
    assert!(toml(&format!("{HEAD}[limits]\nartifact_count = 5000")).is_err());
    assert!(toml(&format!("{HEAD}[limits]\nmemory = -5")).is_err());
}

#[test]
fn all_errors_reported_not_just_first() {
    let src =
        format!("{HEAD}[limits]\nmemory = \"8GiB\"\nwall_clock = \"2d\"\n[env]\nlower = \"x\"");
    let e = toml(&src).expect_err("invalid");
    assert_eq!(e.len(), 3, "{e}");
}

#[test]
fn version_and_name_validated() {
    assert!(err_text("version = 2\nname = \"t\"").contains("schema version"));
    assert!(err_text("version = 1\nname = \"Bad Name\"").contains("name"));
    assert!(toml("name = \"t\"").is_err(), "version is required");
}

// ---- R4/R5: guest path rules ----

#[test]
fn guest_paths_validated() {
    let h = host_dir();
    let mount = |g: &str| {
        format!("{HEAD}[[filesystem.mount]]\nguest = \"{g}\"\nhost = \"{h}\"\nmode = \"ro\"")
    };
    for bad in [
        "data",
        "/a/../b",
        "/a/./b",
        "/",
        "/in",
        "/in/sub",
        "/out",
        "/usr",
        "/usr/local/lib/python3.15",
        "/dev/sandbox/x",
        "/code",
        "/a\\\\b",
        "/a//b",
    ] {
        assert!(
            toml(&mount(bad)).is_err(),
            "guest {bad:?} should be rejected"
        );
    }
    assert!(toml(&mount("/data/")).is_ok());
    let two = format!(
        "{}\n[[filesystem.mount]]\nguest = \"/data/sub\"\nhost = \"{h}\"\nmode = \"ro\"",
        mount("/data")
    );
    assert!(err_text(&two).contains("may not nest"));
    assert!(
        toml(&format!(
            "{HEAD}[filesystem]\ninputs = \"/x\"\noutputs = \"/x/y\""
        ))
        .is_err()
    );
    assert!(toml(&format!("{HEAD}[filesystem]\noutputs = \"/\"")).is_err());
}

// ---- R6: host path rules ----

#[test]
fn host_paths_validated() {
    let m = |host: &str| {
        format!("{HEAD}[[filesystem.mount]]\nguest = \"/d\"\nhost = \"{host}\"\nmode = \"ro\"")
    };
    assert!(err_text(&m("relative/dir")).contains("absolute"));
    assert!(toml(&m("/definitely/not/here/sandboxd")).is_err());
    let h = host_dir();
    assert!(
        toml(&m(&format!("{h}/../sandboxd-policy-tests-host"))).is_err(),
        "'..' rejected"
    );

    let opts = LoadOptions {
        forbidden_host_roots: vec![PathBuf::from(&h)],
    };
    let e = Policy::parse(&m(&h), "t", Format::Toml, &opts).expect_err("forbidden");
    assert!(e.to_string().contains("sandboxd-internal"), "{e}");
}

// ---- env ----

#[test]
fn env_rules_and_no_value_leak() {
    assert!(toml(&format!("{HEAD}[env]\nPYTHONPATH = \"/x\"")).is_err());
    assert!(toml(&format!("{HEAD}[env]\nSANDBOXD_X = \"1\"")).is_err());
    assert!(toml(&format!("{HEAD}[env]\n\"1BAD\" = \"1\"")).is_err());
    let e = err_text(&format!("{HEAD}[env]\nlower = \"hunter2-secret\""));
    assert!(
        !e.contains("hunter2"),
        "values must never appear in errors: {e}"
    );
    assert!(toml(&format!("{HEAD}[env]\nTZ = \"UTC\"")).is_ok());
}

// ---- R12: YAML hardening ----

#[test]
fn yaml_hardening() {
    let alias = "version: 1\nname: t\ndescription: &d hello\nenv:\n  A: *d\n";
    assert!(
        Policy::from_yaml(alias, "y").is_err(),
        "aliases/anchors are refused"
    );
    let dup = "version: 1\nname: t\nname: u\n";
    assert!(
        Policy::from_yaml(dup, "y").is_err(),
        "duplicate keys are refused"
    );
    let multi = "version: 1\nname: t\n---\nversion: 1\nname: u\n";
    assert!(
        Policy::from_yaml(multi, "y").is_err(),
        "single document only"
    );
    let merge = "version: 1\nname: t\nlimits:\n  <<: {memory: 1GiB}\n";
    assert!(
        Policy::from_yaml(merge, "y").is_err(),
        "merge keys are not expanded"
    );
    let huge = format!(
        "version: 1\nname: t\ndescription: {}\n",
        "x".repeat(MAX_POLICY_FILE_BYTES)
    );
    assert!(Policy::from_yaml(&huge, "y").is_err());
}

// ---- Q3: phases 4/5 ----

#[test]
fn session_enabled_is_unsupported_but_valid() {
    let p = toml(&format!("{HEAD}[session]\nenabled = true")).expect("valid shape");
    assert!(p.ensure_supported().is_err());
    assert!(
        toml(&format!("{HEAD}[network]\nmax_requests = 3"))
            .expect("valid")
            .ensure_supported()
            .is_ok()
    );
}

// ---- R8: tighten ----

#[test]
fn tighten_lowers_and_refuses_widening() {
    let p = toml(HEAD).expect("valid");
    let t = p
        .tighten(&Overrides {
            memory: Some(ByteSize::mib(64)),
            wall_clock: Some(Duration::from_secs(1)),
            ..Default::default()
        })
        .expect("tighten");
    assert_eq!(t.limits().memory, ByteSize::mib(64));
    assert_eq!(t.limits().wall_clock, Duration::from_secs(1));
    assert_eq!(t.limits().fuel, p.limits().fuel);

    let e = p
        .tighten(&Overrides {
            memory: Some(ByteSize::gib(1)),
            ..Default::default()
        })
        .expect_err("widen");
    assert!(
        matches!(
            e,
            PolicyError::WouldWiden {
                field: "limits.memory",
                ..
            }
        ),
        "{e}"
    );
    assert!(
        p.tighten(&Overrides {
            wall_clock: Some(Duration::ZERO),
            ..Default::default()
        })
        .is_err()
    );
    assert_eq!(p.tighten(&Overrides::default()).expect("noop"), p);
}

proptest! {
    #[test]
    fn tighten_never_widens(mem in 0u64..(8u64 << 30), wall in 0u64..10_000_000, fuel in 0u64..5_000_000_000_000u64, out in 0u64..(256u64 << 20)) {
        let p = Policy::builtin_default();
        let o = Overrides {
            memory: Some(ByteSize(mem)),
            wall_clock: Some(Duration::from_millis(wall)),
            fuel: Some(fuel),
            stdout: Some(ByteSize(out)),
            ..Default::default()
        };
        if let Ok(t) = p.tighten(&o) {
            let (a, b) = (t.limits(), p.limits());
            prop_assert!(a.memory <= b.memory && a.wall_clock <= b.wall_clock && a.fuel <= b.fuel && a.stdout <= b.stdout);
        }
    }

    #[test]
    fn byte_parser_is_exact_for_integers(n in 0u64..1_000_000, unit in prop::sample::select(vec![("", 1u64), ("kb", 1024), ("MiB", 1 << 20), ("g", 1 << 30)])) {
        let parsed = parse_bytes(&format!("{n}{}", unit.0));
        prop_assert_eq!(parsed, Ok(ByteSize(n * unit.1)));
    }

    #[test]
    fn parsers_never_panic(s in "\\PC{0,24}") {
        let _ = parse_bytes(&s);
        let _ = parse_duration(&s);
        let _ = parse_fuel(&s);
        let _ = Policy::from_toml(&s, "x");
        let _ = Policy::from_yaml(&s, "y");
    }
}

// ---- R7/R9: directory loading ----

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sandboxd-policydir-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

#[test]
fn dir_loads_mixed_formats_and_builtin_default() {
    let d = tmpdir("ok");
    std::fs::write(d.join("alpha.toml"), "version = 1\nname = \"alpha\"").expect("w");
    std::fs::write(d.join("beta.yml"), "version: 1\nname: beta\n").expect("w");
    std::fs::write(d.join("README.md"), "ignored").expect("w");
    std::fs::write(d.join(".hidden.toml"), "garbage").expect("w");
    let dir = PolicyDir::load(&d, &LoadOptions::default()).expect("load");
    let names: Vec<_> = dir.list().into_iter().map(|s| s.name).collect();
    assert_eq!(names, vec!["alpha", "beta", "default"]);
    assert!(dir.get("alpha").is_ok());
    assert!(matches!(dir.get("nope"), Err(PolicyError::NotFound(_))));
    assert!(!dir.list().iter().any(|s| s.overrides_builtin));
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn dir_load_is_all_or_nothing_and_reports_everything() {
    let d = tmpdir("bad");
    std::fs::write(d.join("good.toml"), "version = 1\nname = \"good\"").expect("w");
    std::fs::write(d.join("wrongname.toml"), "version = 1\nname = \"other\"").expect("w");
    std::fs::write(d.join("dup.toml"), "version = 1\nname = \"dup\"").expect("w");
    std::fs::write(d.join("dup.yaml"), "version: 1\nname: dup\n").expect("w");
    std::fs::write(
        d.join("net.toml"),
        "version = 1\nname = \"net\"\n[network]\ntcp = [{ host = \"db\", port = 5432 }]",
    )
    .expect("w");
    std::fs::write(d.join("broken.yaml"), "version: [\n").expect("w");
    let e = PolicyDir::load(&d, &LoadOptions::default()).expect_err("must fail");
    let text = e.to_string();
    for needle in [
        "wrongname",
        "duplicate policy name",
        "network broker",
        "broken.yaml",
    ] {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn operator_can_override_default_and_policy_dir_is_not_mountable() {
    let d = tmpdir("override");
    std::fs::write(
        d.join("default.toml"),
        "version = 1\nname = \"default\"\n[limits]\nmemory = \"64MiB\"",
    )
    .expect("w");
    let dir = PolicyDir::load(&d, &LoadOptions::default()).expect("load");
    assert_eq!(
        dir.get("default").expect("get").limits().memory,
        ByteSize::mib(64)
    );
    assert!(dir.list().iter().any(|s| s.overrides_builtin));

    let host = d.display().to_string().replace('\\', "/");
    std::fs::write(d.join("sneaky.toml"), format!("version = 1\nname = \"sneaky\"\n[[filesystem.mount]]\nguest = \"/p\"\nhost = \"{host}\"\nmode = \"ro\"")).expect("w");
    let e =
        PolicyDir::load(&d, &LoadOptions::default()).expect_err("policy dir must not be mountable");
    assert!(e.to_string().contains("sandboxd-internal"));
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn explain_shows_warnings_without_env_values() {
    let h = host_dir();
    let p = toml(&format!("{HEAD}[[filesystem.mount]]\nguest = \"/w\"\nhost = \"{h}\"\nmode = \"rw\"\n[env]\nAPI_HINT = \"very-secret\"\n[audit]\nlog_code = true")).expect("valid");
    let x = p.explain();
    assert!(
        x.contains("read-write host mount") && x.contains("log_code = true"),
        "{x}"
    );
    assert!(x.contains("API_HINT") && !x.contains("very-secret"), "{x}");
}
