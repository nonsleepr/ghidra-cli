//! Integration tests for output format flags

/// Helper to verify Ghidra is installed before running tests
fn require_ghidra() {
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("doctor")
        .output()
        .expect("Failed to run ghidra doctor");

    if !output.status.success() {
        panic!("Ghidra is not installed. Tests require Ghidra installation per AGENTS.md");
    }
}

#[test]
fn test_help_shows_json_flag() {
    require_ghidra();

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
    require_ghidra();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("--json")
        .arg("--help")
        .assert()
        .success();
}

#[test]
fn test_format_flag_accepted() {
    require_ghidra();

    // Valid formats should be accepted
    for fmt in &["compact", "json", "count"] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("version")
            .arg("-o")
            .arg(fmt)
            .assert()
            .success();
    }
}
