//! C3-U2 pooling allocator tests (FR-P1, AC 1).

use std::sync::{Arc, OnceLock};

use sandboxd_audit::NullSink;
use sandboxd_policy::Policy;
use sandboxd_runtime::*;
use sandboxd_vfs::VfsConfig;
use wasmtime::{Linker, Module, Store};

fn root() -> std::path::PathBuf {
    std::env::temp_dir().join("sandboxd-runtime-tests")
}

fn cfg(pooling: PoolingMode, slots: u32) -> RuntimeConfig {
    RuntimeConfig {
        vfs: VfsConfig::under(root()),
        pooling,
        pool_slots: slots,
        ..RuntimeConfig::default()
    }
}

fn build(c: RuntimeConfig) -> Result<(Sandbox, WarmupReport), RuntimeError> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("rt");
        rt.block_on(Sandbox::new(c, Arc::new(NullSink)))
    })
    .join()
    .expect("thread")
}

/// The default configuration (pooling `auto`, 64 slots), shared by the tests below.
fn pooled() -> &'static (Sandbox, WarmupReport) {
    static S: OnceLock<(Sandbox, WarmupReport)> = OnceLock::new();
    S.get_or_init(|| build(cfg(PoolingMode::Auto, 64)).expect("sandbox"))
}

fn policy() -> Arc<Policy> {
    Arc::new(Policy::builtin_default())
}

/// `(module (memory (export "mem") 1 64))`, hand-assembled.
const MEMORY_ONLY: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version
    0x05, 0x04, 0x01, 0x01, 0x01, 0x40, // memory section: 1 memory, min 1, max 64 pages
    0x07, 0x07, 0x01, 0x03, b'm', b'e', b'm', 0x02, 0x00, // export "mem" = memory 0
];

#[tokio::test(flavor = "multi_thread")]
async fn pooled_memory_is_reset_between_instances() {
    let (sb, report) = pooled();
    assert!(
        report.pooling,
        "pooling should be active: {:?}",
        report.pooling_fallback
    );
    let engine = sb.engine();
    let module = Module::new(engine, MEMORY_ONLY).expect("module");
    let linker: Linker<()> = Linker::new(engine);
    // Each instance must see an all-zero memory, then fills all 64 pages with a canary. With
    // slot reuse (affinity to the same module) any remnant of the previous instance shows up.
    for i in 0..200 {
        let mut store = Store::new(engine, ());
        let inst = linker
            .instantiate_async(&mut store, &module)
            .await
            .expect("instantiate");
        let mem = inst.get_memory(&mut store, "mem").expect("mem");
        mem.grow(&mut store, 63).expect("grow to 64 pages");
        let data = mem.data_mut(&mut store);
        assert_eq!(data.len(), 64 * 65536);
        if let Some(pos) = data.iter().position(|&b| b != 0) {
            panic!(
                "instance {i}: byte {pos} = {:#x} left over from a previous instance",
                data[pos]
            );
        }
        data.fill(0xA5);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_work_and_slots_are_released() {
    let (sb, _) = pooled();
    for lang in [Language::Python, Language::JavaScript] {
        let code = if lang == Language::Python {
            "print(sum(range(10)))"
        } else {
            "console.log([...Array(10).keys()].reduce((a, b) => a + b))"
        };
        let r = sb
            .execute(RunRequest::new(lang, code), policy(), "t", None)
            .await;
        assert_eq!(
            r.outcome,
            Outcome::Ok,
            "{lang}: {:?}",
            String::from_utf8_lossy(&r.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), "45");
    }
    let st = sb.pool_status().expect("pooling");
    assert_eq!(st.slots, 64);
    assert_eq!(st.in_use, 0, "every slot released after the runs");
}

#[tokio::test(flavor = "multi_thread")]
async fn more_concurrent_runs_than_slots_wait_instead_of_failing() {
    // FR-P1.3: two slots, eight concurrent runs: all succeed (they queue for a slot).
    static TWO: OnceLock<(Sandbox, WarmupReport)> = OnceLock::new();
    let (sb, report) = TWO.get_or_init(|| build(cfg(PoolingMode::On, 2)).expect("sandbox"));
    assert!(report.pooling);
    let mut hs = Vec::new();
    for i in 0..8 {
        let sb = sb.clone();
        hs.push(tokio::spawn(async move {
            sb.execute(
                RunRequest::new(Language::JavaScript, format!("console.log({i})")),
                policy(),
                "t",
                None,
            )
            .await
        }));
    }
    for (i, h) in hs.into_iter().enumerate() {
        let r = h.await.expect("join");
        assert_eq!(r.outcome, Outcome::Ok, "run {i}: {:?}", r.error);
        assert_eq!(String::from_utf8_lossy(&r.stdout).trim(), i.to_string());
    }
    assert_eq!(sb.pool_status().map(|s| s.in_use), Some(0));
}

#[test]
fn auto_falls_back_and_on_fails_when_the_pool_cannot_be_created() {
    // A zero-slot pool can't be built: `auto` falls back to on-demand, `on` refuses to start.
    let (sb, report) = build(cfg(PoolingMode::Auto, 0)).expect("auto falls back");
    assert!(!report.pooling);
    assert!(report.pooling_fallback.is_some());
    assert!(sb.pool_status().is_none());
    assert!(build(cfg(PoolingMode::On, 0)).is_err());
}

#[test]
fn off_uses_on_demand_allocation() {
    let (sb, report) = build(cfg(PoolingMode::Off, 64)).expect("sandbox");
    assert!(!report.pooling && report.pooling_fallback.is_none());
    assert!(sb.pool_status().is_none());
}

#[test]
fn pooling_mode_parses() {
    assert_eq!(PoolingMode::parse("AUTO"), Some(PoolingMode::Auto));
    assert_eq!(PoolingMode::parse("on"), Some(PoolingMode::On));
    assert_eq!(PoolingMode::parse("off"), Some(PoolingMode::Off));
    assert_eq!(PoolingMode::parse("sometimes"), None);
}
