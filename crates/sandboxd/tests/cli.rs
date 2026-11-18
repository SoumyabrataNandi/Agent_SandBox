//! End-to-end tests of the real `sandboxd` binary (AC 1, 2, 7, 8 via the CLI and stdio MCP).

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, ContentBlock},
    transport::TokioChildProcess,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sandboxd")
}

/// A scratch dir with a config that reuses the runtime tests' compiled cache.
fn setup(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sandboxd-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("policies")).expect("mkdir");
    let cache = std::env::temp_dir()
        .join("sandboxd-runtime-tests")
        .join("cache");
    let toml = format!(
        "policy_dir = \"policies\"\ncache_dir = {cache:?}\nwork_dir = \"work\"\n[audit]\nsink = \"file\"\npath = \"audit.jsonl\"\n",
        cache = cache.display().to_string().replace('\\', "/")
    );
    std::fs::write(dir.join("sandboxd.toml"), toml).expect("config");
    std::fs::write(dir.join("policies/tight.toml"), "version = 1\nname = \"tight\"\ndescription = \"1s, 64MiB\"\n[limits]\nwall_clock = \"1s\"\nmemory = \"64MiB\"\n").expect("policy");
    dir
}

fn sbx(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("SANDBOXD_CONFIG", dir.join("sandboxd.toml"))
        .current_dir(dir)
        .output()
        .expect("spawn sandboxd")
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn run_python_with_input_and_artifact() {
    let d = setup("run");
    std::fs::write(d.join("job.py"), "import json\nn = len(open('/in/data.csv').read().splitlines())\nprint('lines', n)\njson.dump({'n': n}, open('/out/out.json','w'))\n").expect("w");
    std::fs::write(d.join("data.csv"), "a\nb\nc\n").expect("w");
    let o = sbx(
        &d,
        &["run", "job.py", "--input", "data.csv", "--out", "artifacts"],
    );
    assert_eq!(o.status.code(), Some(0), "stderr: {}", s(&o.stderr));
    assert_eq!(s(&o.stdout), "lines 3\n");
    assert_eq!(
        std::fs::read_to_string(d.join("artifacts/out.json")).expect("artifact"),
        "{\"n\": 3}"
    );
    let audit = std::fs::read_to_string(d.join("audit.jsonl")).expect("audit file");
    assert!(
        audit.contains("\"event\":\"run.start\"") && audit.contains("\"principal\":\"cli\""),
        "{audit}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn run_exit_statuses() {
    let d = setup("status");
    std::fs::write(d.join("hello.js"), "console.log('js ok')").expect("w");
    std::fs::write(d.join("loop.py"), "while True:\n    pass\n").expect("w");
    std::fs::write(d.join("fail.py"), "raise SystemExit(7)").expect("w");
    let o = sbx(&d, &["run", "hello.js"]);
    assert_eq!((o.status.code(), s(&o.stdout)), (Some(0), "js ok\n".into()));
    let o = sbx(&d, &["run", "loop.py", "--policy", "tight"]);
    assert_eq!(o.status.code(), Some(3), "limit → 3: {}", s(&o.stderr));
    assert!(s(&o.stderr).contains("wall_clock"));
    assert_eq!(sbx(&d, &["run", "fail.py"]).status.code(), Some(1));
    let o = sbx(
        &d,
        &["run", "hello.js", "--policy", "tight", "--memory", "1gb"],
    );
    assert_eq!(
        o.status.code(),
        Some(2),
        "widening → usage error: {}",
        s(&o.stderr)
    );
    assert_eq!(
        sbx(&d, &["run", "hello.js", "--policy", "missing"])
            .status
            .code(),
        Some(2)
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn policy_check_token_and_version() {
    let d = setup("policy");
    let o = sbx(&d, &["policy", "check", "policies/tight.toml"]);
    assert_eq!(o.status.code(), Some(0), "{}", s(&o.stderr));
    assert!(s(&o.stdout).contains("wall_clock      1s"));
    std::fs::write(
        d.join("bad.toml"),
        "version = 1\nname = \"bad\"\n[limits]\nmemory = \"9GiB\"\n",
    )
    .expect("w");
    assert_eq!(
        sbx(&d, &["policy", "check", "bad.toml"]).status.code(),
        Some(4)
    );
    let o = sbx(&d, &["policy", "list"]);
    assert!(s(&o.stdout).contains("tight") && s(&o.stdout).contains("default"));
    let o = sbx(&d, &["token", "new", "--name", "ci"]);
    assert!(s(&o.stdout).contains("sbx_") && s(&o.stdout).contains("name = \"ci\", sha256 = \""));
    assert!(s(&sbx(&d, &["version"]).stdout).contains("quickjs-ng 0.18.0"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ac8_serve_refuses_public_bind_without_tokens() {
    let d = setup("bind");
    let o = Command::new(bin())
        .args(["serve", "--listen", "0.0.0.0:0"])
        .env("SANDBOXD_CONFIG", d.join("sandboxd.toml"))
        .env_remove("SANDBOXD_TOKEN")
        .output()
        .expect("spawn");
    assert_eq!(o.status.code(), Some(5));
    assert!(
        s(&o.stderr).contains("refusing to listen"),
        "{}",
        s(&o.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// AC 7: exactly how Claude Desktop / Claude Code launch it: `sandboxd mcp` over stdio.
#[tokio::test(flavor = "multi_thread")]
async fn ac7_mcp_stdio_child_process() {
    let d = setup("mcp");
    let mut cmd = tokio::process::Command::new(bin());
    cmd.arg("mcp")
        .env("SANDBOXD_CONFIG", d.join("sandboxd.toml"))
        .current_dir(&d);
    let transport = TokioChildProcess::new(cmd).expect("spawn mcp");
    let client = ().serve(transport).await.expect("initialize");
    let tools = client.list_all_tools().await.expect("list tools");
    assert!(tools.iter().any(|t| t.name == "run_code"));
    let args = serde_json::json!({"language": "python", "code": "import statistics\nprint(statistics.mean([1, 2, 3, 4]))", "policy": "tight"});
    let r = client
        .call_tool(
            CallToolRequestParams::new("run_code")
                .with_arguments(args.as_object().cloned().unwrap_or_default()),
        )
        .await
        .expect("call");
    let text: String = r
        .content
        .iter()
        .filter_map(|c| {
            if let ContentBlock::Text(t) = c {
                Some(t.text.clone())
            } else {
                None
            }
        })
        .collect();
    assert!(
        text.contains("2.5") && text.contains("outcome: ok"),
        "{text}"
    );
    let _ = client.cancel().await;
    let audit = std::fs::read_to_string(d.join("audit.jsonl")).unwrap_or_default();
    assert!(audit.contains("\"principal\":\"mcp-stdio\""), "{audit}");
    let _ = std::fs::remove_dir_all(&d);
}
