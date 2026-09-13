//! SecPilot privileged helper.
//!
//! The Python application stays unprivileged. This binary accepts a single JSON
//! request on stdin and runs one allowlisted argv vector. It never evaluates a
//! shell string and never accepts a free-form command from a model.

use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug, Deserialize)]
struct HelperRequest {
    op: String,
    argv: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HelperResult {
    tool: String,
    category: String,
    target: String,
    argv: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    parsed: serde_json::Value,
    duration_ms: u128,
    privileged: bool,
}

const ALLOWED_BINARIES: &[&str] = &["nmap", "tshark", "tcpdump", "journalctl", "lynis"];

fn main() {
    let mut raw = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut raw) {
        fail(&format!("failed to read stdin: {error}"));
    }
    let request: HelperRequest = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(error) => fail(&format!("invalid request: {error}")),
    };
    if request.argv.is_empty() {
        fail("argv must not be empty");
    }
    let binary = request.argv[0].as_str();
    if !ALLOWED_BINARIES.contains(&binary) {
        fail(&format!("binary '{binary}' is not allowlisted"));
    }
    if request.argv.iter().any(|part| part.contains('\0')) {
        fail("nul byte in argv");
    }

    let started = Instant::now();
    let output = Command::new(binary)
        .args(&request.argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = match output {
        Ok(value) => value,
        Err(error) => fail(&format!("execution failed: {error}")),
    };

    let result = HelperResult {
        tool: binary.to_string(),
        category: request.op,
        target: request
            .argv
            .last()
            .cloned()
            .unwrap_or_default(),
        argv: request.argv,
        exit_code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        parsed: serde_json::json!({}),
        duration_ms: started.elapsed().as_millis(),
        privileged: true,
    };
    println!("{}", serde_json::to_string(&result).expect("serialize"));
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}
