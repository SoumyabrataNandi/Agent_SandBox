use std::{
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use sandboxd_audit::*;
use serde_json::{Value, json};

fn fixed() -> (SystemTime, RunId) {
    let ts = SystemTime::UNIX_EPOCH + Duration::from_millis(1_795_000_000_123);
    let id = RunId::from_uuid(uuid::Uuid::from_u128(
        0x0193_0000_0000_7000_8000_0000_0000_0001,
    ));
    (ts, id)
}

fn line(kind: EventKind) -> Value {
    let (ts, id) = fixed();
    let ev = AuditEvent::new(kind)
        .at(ts)
        .run(id)
        .policy("default")
        .principal("ci-bot");
    serde_json::from_str(&ev.to_json_line(&Redactor::new())).expect("valid json")
}

#[test]
fn envelope_and_run_start_golden() {
    let v = line(EventKind::RunStart {
        lang: "python".into(),
        code_sha256: sha256_hex(b"print(1)"),
        code_bytes: 8,
        code: None,
        inputs: vec![FileDigest {
            name: "a.csv".into(),
            bytes: 3,
            sha256: sha256_hex(b"a,b"),
        }],
    });
    assert_eq!(
        v,
        json!({
            "ts": "2026-11-18T11:06:40.123Z", "v": 1,
            "run_id": "01930000-0000-7000-8000-000000000001",
            "policy": "default", "principal": "ci-bot",
            "event": "run.start", "lang": "python",
            "code_sha256": sha256_hex(b"print(1)"), "code_bytes": 8,
            "inputs": [{"name": "a.csv", "bytes": 3, "sha256": sha256_hex(b"a,b")}]
        })
    );
}

#[test]
fn every_event_kind_serializes_with_expected_name() {
    let cases: Vec<(EventKind, &str)> = vec![
        (
            EventKind::RunEnd {
                outcome: Outcome::Limit,
                exit_code: None,
                duration_ms: 2001,
                fuel_used: Some(5),
                peak_memory: Some(1 << 20),
                limits_hit: vec![LimitKind::WallClock],
                stdout_bytes: 0,
                stderr_bytes: 0,
                artifacts: vec![],
            },
            "run.end",
        ),
        (
            EventKind::FsAccess {
                op: FsOp::Open,
                path: "/etc/passwd".into(),
                mode: Some("r".into()),
                decision: Decision::Deny,
                reason: Some("outside mounts".into()),
            },
            "fs.access",
        ),
        (
            EventKind::EnvRead {
                key: "HOME".into(),
                decision: Decision::Deny,
            },
            "env.read",
        ),
        (
            EventKind::LimitHit {
                kind: LimitKind::Memory,
                limit: 1,
                observed: 2,
            },
            "limit.hit",
        ),
        (
            EventKind::PolicyDenied {
                what: "widen".into(),
                requested: None,
            },
            "policy.denied",
        ),
        (
            EventKind::NetRequest {
                proto: "http".into(),
                host: "h".into(),
                ip: None,
                port: 443,
                method: None,
                path: None,
                status: None,
                bytes_out: 0,
                bytes_in: 0,
                decision: Decision::Deny,
            },
            "net.request",
        ),
        (EventKind::Dropped { count: 3 }, "audit.dropped"),
        (
            EventKind::ServerStart {
                version: "0.1.0".into(),
                asset_pins: vec![],
                policies: vec![],
            },
            "server.start",
        ),
        (EventKind::ServerStop, "server.stop"),
    ];
    for (kind, name) in cases {
        let v = line(kind);
        assert_eq!(v["event"], name);
        assert_eq!(v["v"], 1);
    }
    let v = line(EventKind::RunEnd {
        outcome: Outcome::Limit,
        exit_code: None,
        duration_ms: 1,
        fuel_used: None,
        peak_memory: None,
        limits_hit: vec![LimitKind::WallClock, LimitKind::Cpu],
        stdout_bytes: 0,
        stderr_bytes: 0,
        artifacts: vec![],
    });
    assert_eq!(v["outcome"], "limit");
    assert_eq!(v["limits_hit"], json!(["wall_clock", "cpu"]));
}

#[test]
fn free_text_is_redacted_and_truncated() {
    let v = line(EventKind::PolicyDenied {
        what: format!("token=abcdef {}", "x".repeat(10_000)),
        requested: Some("Bearer zzz".into()),
    });
    let what = v["what"].as_str().expect("str");
    assert!(what.starts_with("token=[REDACTED:kv]"));
    assert!(what.contains("…[truncated "));
    assert!(what.len() < MAX_FIELD_BYTES + 64);
    assert_eq!(v["requested"], "Bearer [REDACTED:bearer]");

    let code = line(EventKind::RunStart {
        lang: "python".into(),
        code_sha256: String::new(),
        code_bytes: 0,
        code: Some(format!(
            "KEY='sk-ant-api03-ABCDEFGHIJKLMNOP'\n{}",
            "#".repeat(100_000)
        )),
        inputs: vec![],
    });
    let c = code["code"].as_str().expect("str");
    assert!(c.contains("[REDACTED:anthropic]") && !c.contains("ABCDEFGHIJKLMNOP"));
    assert!(c.len() < MAX_CODE_BYTES + 64);
}

#[test]
fn token_principal_never_contains_token() {
    let p = token_principal("super-secret-token-value");
    assert!(p.starts_with("token:") && p.len() == 18 && !p.contains("secret"));
}

/// Shared in-memory writer whose failure can be toggled.
#[derive(Clone, Default)]
struct Buf {
    data: Arc<Mutex<Vec<u8>>>,
    fail: Arc<AtomicBool>,
}
impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("disk full"));
        }
        self.data.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Buf {
    fn lines(&self) -> Vec<Value> {
        let d = self.data.lock().expect("lock");
        String::from_utf8_lossy(&d)
            .lines()
            .map(|l| serde_json::from_str(l).expect("each line is json"))
            .collect()
    }
}

fn opts() -> JsonlOptions {
    JsonlOptions {
        retry: Duration::from_millis(20),
        ..JsonlOptions::default()
    }
}

#[test]
fn jsonl_writes_everything_and_shutdown_flushes() {
    let buf = Buf::default();
    let sink = JsonlSink::to_writer(Box::new(buf.clone()), Redactor::new(), opts());
    for i in 0..500 {
        sink.emit(AuditEvent::new(EventKind::Dropped { count: i }));
    }
    sink.emit(AuditEvent::new(EventKind::ServerStop));
    sink.shutdown();
    let lines = buf.lines();
    assert_eq!(lines.len(), 501);
    assert_eq!(lines.last().expect("last")["event"], "server.stop");
    sink.shutdown(); // idempotent
}

#[test]
fn full_queue_drops_are_counted_and_reported() {
    let buf = Buf::default();
    buf.fail.store(true, Ordering::SeqCst); // stall the writer so the queue fills
    let sink = JsonlSink::to_writer(
        Box::new(buf.clone()),
        Redactor::new(),
        JsonlOptions {
            queue: 2,
            max_pending_bytes: 1 << 20,
            ..opts()
        },
    );
    for _ in 0..200 {
        sink.emit(AuditEvent::new(EventKind::ServerStop));
    }
    buf.fail.store(false, Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(150));
    sink.shutdown();
    let lines = buf.lines();
    let written = lines.iter().filter(|l| l["event"] == "server.stop").count() as u64;
    let reported: u64 = lines
        .iter()
        .filter(|l| l["event"] == "audit.dropped")
        .map(|l| l["count"].as_u64().expect("count"))
        .sum();
    assert!(reported > 0, "expected some drops");
    assert_eq!(
        written + reported,
        200,
        "every event is either written or counted"
    );
}

#[test]
fn health_goes_false_on_write_failure_and_recovers() {
    let buf = Buf::default();
    let sink = JsonlSink::to_writer(Box::new(buf.clone()), Redactor::new(), opts());
    assert!(sink.is_healthy());
    buf.fail.store(true, Ordering::SeqCst);
    sink.emit(AuditEvent::new(EventKind::ServerStop));
    let t = std::time::Instant::now();
    while sink.is_healthy() && t.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!sink.is_healthy(), "should fail closed");
    buf.fail.store(false, Ordering::SeqCst);
    let t = std::time::Instant::now();
    while !sink.is_healthy() && t.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(sink.is_healthy(), "should recover and retry pending lines");
    sink.shutdown();
    assert_eq!(
        buf.lines().len(),
        1,
        "the pending event was written after recovery"
    );
}

#[test]
fn file_sink_appends() {
    let dir = std::env::temp_dir().join(format!("sandboxd-audit-test-{}", RunId::new()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join("audit.jsonl");
    for _ in 0..2 {
        let s = JsonlSink::to_file(&path, Redactor::new(), opts()).expect("open");
        s.emit(AuditEvent::new(EventKind::ServerStop));
        s.shutdown();
    }
    let text = std::fs::read_to_string(&path).expect("read");
    assert_eq!(text.lines().count(), 2);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn fanout_health_is_conjunction() {
    struct Bad;
    impl AuditSink for Bad {
        fn emit(&self, _: AuditEvent) {}
        fn is_healthy(&self) -> bool {
            false
        }
    }
    let mem = Arc::new(MemorySink::default());
    let f = FanoutSink(vec![mem.clone(), Arc::new(NullSink)]);
    f.emit(AuditEvent::new(EventKind::ServerStop));
    assert_eq!(mem.events().len(), 1);
    assert!(f.is_healthy());
    assert!(!FanoutSink(vec![mem, Arc::new(Bad)]).is_healthy());
}
