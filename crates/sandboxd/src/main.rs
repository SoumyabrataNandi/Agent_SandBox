//! `sandboxd`: run untrusted, agent-generated code in a WebAssembly sandbox.
//!
//! U0 ships only `sandboxd version`. The full CLI (`run`, `serve`, `mcp`, `policy`, `cache`)
//! arrives in U5.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn print_version() {
    println!("sandboxd {}", env!("CARGO_PKG_VERSION"));
    for a in sandboxd_assets::ALL {
        println!(
            "  {:<11} {:<18} sha256:{}  {:>6.1} MiB  ({})",
            a.name,
            a.version,
            a.sha256,
            a.bytes.len() as f64 / (1024.0 * 1024.0),
            a.license
        );
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("version" | "--version" | "-V") => {
            print_version();
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: sandboxd version\n(more commands arrive in later units)");
            ExitCode::from(2)
        }
    }
}
