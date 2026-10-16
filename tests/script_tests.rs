//! Script execution must actually work; expected failures are tested separately.
use serial_test::serial;
use std::sync::OnceLock;
#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};
const TEST_PROJECT: &str = "ci-test-script";
const TEST_PROGRAM: &str = "sample_binary";
static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();
fn cli(args: &[&str]) -> std::process::Output {
    require_ghidra!();
    HARNESS.get_or_init(|| {
        ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).unwrap()
    });
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json"])
        .args(args)
        .args(["--project", TEST_PROJECT, "--program", TEST_PROGRAM])
        .output()
        .unwrap()
}
fn success(output: std::process::Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
#[serial]
fn java_file_paths_helpers_and_arguments() {
    let temp = tempfile::Builder::new()
        .prefix("ghidra script spaces ")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let path = temp.path().join("Probe.java");
    std::fs::write(
        temp.path().join("Helper.java"),
        "public class Helper { public static String message() { return \"HELPER\"; } }",
    )
    .unwrap();
    std::fs::write(&path, "import ghidra.app.script.GhidraScript; public class Probe extends GhidraScript { public void run() { println(Helper.message() + currentProgram.getName() + getScriptArgs()[0]); printerr(\"ERR_PROBE\"); } }").unwrap();
    // Put args after --; project options must precede it.
    for input in [
        path.clone(),
        path.strip_prefix(std::env::current_dir().unwrap())
            .unwrap()
            .to_path_buf(),
    ] {
        let mut output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli");
        output.args(["--json", "script", "run"]).arg(input).args([
            "--project",
            TEST_PROJECT,
            "--program",
            TEST_PROGRAM,
            "--",
            "ARG_PROBE",
        ]);
        // Initialize before executing the independently built command.
        success(cli(&["program", "info"]));
        let value = success(output.output().unwrap());
        assert!(value["stdout"]
            .as_str()
            .unwrap()
            .contains("HELPERsample_binaryARG_PROBE"));
        assert!(value["stderr"].as_str().unwrap().contains("ERR_PROBE"));
    }
}
#[test]
#[serial]
fn inline_java_and_failures_leave_bridge_usable() {
    for _ in 0..2 {
        let value = success(cli(&[
            "script",
            "java",
            "println(currentProgram.getName()); printerr(\"ERR_INLINE\");",
        ]));
        assert!(value["stdout"].as_str().unwrap().contains(TEST_PROGRAM));
        assert!(value["stderr"].as_str().unwrap().contains("ERR_INLINE"));
    }
    for code in [
        "this is not Java;",
        "throw new Exception(\"RUNTIME_PROBE\");",
        "throw new AssertionError(\"ASSERTION_PROBE\");",
    ] {
        let output = cli(&["script", "java", code]);
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
        success(cli(&["program", "info"]));
    }
    let value = success(cli(&["script", "java", "try (var paths = java.nio.file.Files.list(java.nio.file.Path.of(System.getProperty(\"java.io.tmpdir\")))) { println(Long.toString(paths.filter(p -> p.getFileName().toString().startsWith(\"ghidra-cli-inline-\")).count())); }"]));
    // The only matching directory is this invocation's own temporary bundle.
    assert_eq!(value["stdout"].as_str().unwrap().trim(), "1");
}
#[test]
#[serial]
fn failed_scripts_roll_back_program_changes() {
    success(cli(&[
        "script",
        "java",
        "getFunction(\"add_numbers\").setComment(\"before-script\");",
    ]));
    for failure in [
        "new Exception(\"ROLLBACK_PROBE\")",
        "new AssertionError(\"ROLLBACK_PROBE\")",
    ] {
        let code = format!(
            "getFunction(\"add_numbers\").setComment(\"failed-script\"); throw {};",
            failure
        );
        assert!(!cli(&["script", "java", &code]).status.success());
        let value = success(cli(&[
            "script",
            "java",
            "println(getFunction(\"add_numbers\").getComment());",
        ]));
        assert_eq!(value["stdout"].as_str().unwrap().trim(), "before-script");
    }
}
#[test]
#[serial]
fn script_errors_are_explicit() {
    for args in [
        vec!["script", "run", "/nonexistent/Probe.java"],
        vec!["script", "python", "print('unsupported')"],
    ] {
        assert!(!cli(&args).status.success());
    }
}
