//! Signature editing must update the program atomically and persist on close.
use serial_test::serial;
use std::sync::OnceLock;
#[macro_use]
mod common;
use common::{ensure_test_project, DaemonTestHarness};
const PROJECT: &str = "ci-test-signature";
const PROGRAM: &str = "sample_binary";
static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();
fn run(args: &[&str]) -> std::process::Output {
    require_ghidra!();
    HARNESS.get_or_init(|| {
        ensure_test_project(PROJECT, PROGRAM);
        DaemonTestHarness::new(PROJECT, PROGRAM).unwrap()
    });
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("--json")
        .args(args)
        .args(["--project", PROJECT, "--program", PROGRAM])
        .output()
        .unwrap()
}
fn ok(args: &[&str]) -> serde_json::Value {
    let output = run(args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
#[serial]
fn signatures_types_errors_and_persistence() {
    ok(&["script", "java", "var type = new ghidra.program.model.data.TypedefDataType(ghidra.program.model.data.CategoryPath.ROOT, \"RepairWord\", ghidra.program.model.data.UnsignedIntegerDataType.dataType, currentProgram.getDataTypeManager()); currentProgram.getDataTypeManager().addDataType(type, ghidra.program.model.data.DataTypeConflictHandler.DEFAULT_HANDLER);"]);
    for signature in [
        "int different_name(int a, int b)",
        "RepairWord add_numbers(RepairWord *value, char *text)",
        "int add_numbers(char *format, ...)",
    ] {
        let value = ok(&[
            "function",
            "set-signature",
            "add_numbers",
            "--signature",
            signature,
        ]);
        assert_eq!(value["status"], "signature_set");
        // Existing imported/user function names are retained.
        assert_eq!(value["function"], "add_numbers");
        assert_eq!(
            ok(&["function", "get", "add_numbers"])["signature"],
            value["signature"]
        );
    }
    let before = ok(&["function", "get", "add_numbers"]);
    for invalid in [
        "not a declaration",
        "MissingRepairType add_numbers(int a)",
        "void add_numbers(int duplicate, int duplicate)",
        "void add_numbers(struct RollbackRepair *duplicate, int duplicate)",
        "int add_numbers(\"unterminated)",
    ] {
        let output = run(&[
            "function",
            "set-signature",
            "add_numbers",
            "--signature",
            invalid,
        ]);
        assert!(!output.status.success(), "unexpected success: {}", invalid);
        assert!(String::from_utf8_lossy(&output.stderr).contains("signature"));
        let after = ok(&["function", "get", "add_numbers"]);
        assert_eq!(after["signature"], before["signature"]);
    }
    assert_eq!(ok(&["script", "java", "println(String.valueOf(currentProgram.getDataTypeManager().getDataType(\"/RollbackRepair\"))); "])["stdout"].as_str().unwrap().trim(), "null");
    let value = ok(&[
        "function",
        "set-signature",
        "add_numbers",
        "--signature",
        "int add_numbers(int left, int right)",
    ]);
    let decompile = ok(&["decompile", "add_numbers"]);
    assert!(decompile["code"].as_str().unwrap().contains("left"));
    let status = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["stop", "--project", PROJECT])
        .output()
        .unwrap();
    assert!(status.status.success());
    let config = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(config.path(), "ghidra_install_dir: /missing/stale-ghidra\n").unwrap();
    // The valid GHIDRA_INSTALL_DIR inherited from the test environment must win
    // over stale config when reopening the bridge, just as doctor reports.
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .env("GHIDRA_CLI_CONFIG", config.path())
        .args([
            "--json",
            "function",
            "get",
            "add_numbers",
            "--project",
            PROJECT,
            "--program",
            PROGRAM,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        ok(&["function", "get", "add_numbers"])["signature"],
        value["signature"]
    );
}

#[test]
#[serial]
fn default_function_names_can_be_renamed_by_signature() {
    let function = ok(&["function", "get", "multiply"]);
    let address = function["address"].as_str().unwrap();
    ok(&["script", "java", &format!("var f = getFunctionAt(toAddr(\"{}\")); f.setName(\"FUN_{}\", ghidra.program.model.symbol.SourceType.DEFAULT);", address, address)]);
    let edited = ok(&[
        "function",
        "set-signature",
        address,
        "--signature",
        "int repaired_multiply(int x, int y)",
    ]);
    assert_eq!(edited["function"], "repaired_multiply");
    assert_eq!(
        ok(&["function", "get", address])["name"],
        "repaired_multiply"
    );
    // Keep this test repeatable against a persistent test project.
    ok(&["script", "java", &format!("getFunctionAt(toAddr(\"{}\")).setName(\"multiply\", ghidra.program.model.symbol.SourceType.USER_DEFINED);", address)]);
}
