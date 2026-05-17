//! Integration tests for output format flags

#[test]
fn test_help_shows_json_flag() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("--help")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--json"), "Help should show --json flag");
    assert!(
        !stdout.contains("--pretty"),
        "Help should not show removed --pretty flag"
    );
}

#[test]
fn test_json_flag_accepted() {
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("--json")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_format_flag_in_help() {
    // Verify -o / --format appears in subcommand help
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["function", "list", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("-o") || stdout.contains("--format"),
        "function list help should show -o/--format flag"
    );
}
