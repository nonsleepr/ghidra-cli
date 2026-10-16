//! Protocol mismatches must be inspectable without executing a query or restart.
#[macro_use]
mod common;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[test]
fn incompatible_bridge_is_inspectable_and_query_is_rejected() {
    require_ghidra!();
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("identity");
    let state = ghidra_cli::ghidra::bridge::get_data_dir().unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let key = format!("{:x}", md5::compute(project.to_string_lossy().as_bytes()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::fs::write(state.join(format!("bridge-{key}.port")), port.to_string()).unwrap();
    std::fs::write(
        state.join(format!("bridge-{key}.pid")),
        std::process::id().to_string(),
    )
    .unwrap();
    listener.set_nonblocking(true).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let done = finished.clone();
    let server = std::thread::spawn(move || {
        let mut commands = Vec::new();
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut line = String::new();
                    if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let command = request["command"].as_str().unwrap().to_owned();
                    let data = match command.as_str() {
                        "ping" => serde_json::json!({"message":"pong"}),
                        "bridge_info" => {
                            serde_json::json!({"protocol_version":999,"script_hash":"different"})
                        }
                        other => panic!("Unexpected command sent to incompatible bridge: {other}"),
                    };
                    commands.push(command);
                    writeln!(
                        stream,
                        "{}",
                        serde_json::json!({"status":"success","data":data})
                    )
                    .unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("{e}"),
            }
        }
        commands
    });
    let cli = |args: &[&str]| {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args(args)
            .arg("--project")
            .arg(&project)
            .timeout(Duration::from_secs(30))
            .output()
            .unwrap()
    };
    let status = cli(&["status", "--json"]);
    let query = cli(&["program", "info", "--program", "unused"]);
    finished.store(true, Ordering::SeqCst);
    let commands = server.join().unwrap();
    std::fs::remove_file(state.join(format!("bridge-{key}.port"))).unwrap();
    std::fs::remove_file(state.join(format!("bridge-{key}.pid"))).unwrap();
    assert!(status.status.success());
    let info: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(info["compatibility"]["protocol"], "mismatch");
    assert!(!query.status.success());
    assert!(String::from_utf8_lossy(&query.stderr).contains("Bridge protocol 999"));
    assert!(commands.iter().all(|c| c == "ping" || c == "bridge_info"));
}

/// Error payloads must survive IPC and both CLI entry points without changing exit status.
#[test]
fn failed_decompilation_keeps_structured_diagnostics_and_nonzero_exit() {
    require_ghidra!();
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("decompile-failure");
    let state = ghidra_cli::ghidra::bridge::get_data_dir().unwrap();
    std::fs::create_dir_all(&state).unwrap();
    let key = format!("{:x}", md5::compute(project.to_string_lossy().as_bytes()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let port_file = state.join(format!("bridge-{key}.port"));
    let pid_file = state.join(format!("bridge-{key}.pid"));
    std::fs::write(&port_file, port.to_string()).unwrap();
    std::fs::write(&pid_file, std::process::id().to_string()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let done = finished.clone();
    let server = std::thread::spawn(move || {
        while !done.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut line = String::new();
                    if BufReader::new(&stream).read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let response = match request["command"].as_str().unwrap() {
                        "ping" => serde_json::json!({"status":"success","data":{}}),
                        "bridge_info" => {
                            serde_json::json!({"status":"success","data":{"protocol_version":1}})
                        }
                        "program_info" => {
                            serde_json::json!({"status":"success","data":{"name":"fixture"}})
                        }
                        "decompile_v2" => serde_json::json!({
                            "status":"error", "message":"Decompilation failed: decompiler timed out",
                            "data":{"error":"Decompilation failed: decompiler timed out", "name":"fixture",
                                "address":"00401000", "diagnostics":{
                                    "decompiler":{"status":"failed","completed":false,"timed_out":true,
                                        "cancelled":false,"failed_to_start":false,"raw_message":"raw timeout detail\n"},
                                    "semantic_completeness":"not_established", "recovered":null,
                                    "database":{"signature":"int fixture(void)","signature_source":"USER_DEFINED",
                                        "parameters":[]},
                                    "body":{"range_count":1,"total_size":1,"is_contiguous":true,
                                        "ranges":[{"min_address":"00401000","max_address":"00401000","length":1}]}
                                }}
                        }),
                        other => panic!("Unexpected command: {other}"),
                    };
                    writeln!(stream, "{response}").unwrap();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    let mut outputs = Vec::new();
    for command in [
        vec!["decompile", "fixture"],
        vec!["function", "decompile", "fixture"],
    ] {
        for format in ["json", "compact", "count"] {
            outputs.push((
                format,
                assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
                    .args(&command)
                    .args(["-o", format, "--program", "fixture", "--project"])
                    .arg(&project)
                    .timeout(Duration::from_secs(10))
                    .output()
                    .unwrap(),
            ));
        }
    }
    finished.store(true, Ordering::SeqCst);
    server.join().unwrap();
    std::fs::remove_file(port_file).unwrap();
    std::fs::remove_file(pid_file).unwrap();
    for (format, output) in outputs {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("decompiler timed out"));
        match format {
            "json" => {
                let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(value["status"], "error");
                assert_eq!(value["diagnostics"]["decompiler"]["completed"], false);
                assert_eq!(value["diagnostics"]["decompiler"]["timed_out"], true);
                assert_eq!(
                    value["diagnostics"]["decompiler"]["raw_message"],
                    "raw timeout detail\n"
                );
                assert!(value["diagnostics"]["recovered"].is_null());
            }
            "compact" => {
                let value = String::from_utf8(output.stdout).unwrap();
                assert!(value.contains("Decompiler: failed"));
                assert!(value.contains("raw timeout detail"));
                assert!(value.contains("semantic completeness: not established"));
            }
            _ => assert!(output.stdout.is_empty()),
        }
    }
}
