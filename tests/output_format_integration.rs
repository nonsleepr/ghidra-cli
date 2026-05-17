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
fn test_format_flag_accepted() {
    // Valid formats should be accepted (version command doesn't need Ghidra)
    for fmt in &["compact", "json", "count"] {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("version")
            .arg("-o")
            .arg(fmt)
            .assert()
            .success();
    }
}

#[test]
fn test_invalid_format_rejected() {
    // Invalid format should be an error, not silently fall back
    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .arg("version")
        .arg("-o")
        .arg("invalid_format")
        .assert()
        .failure();
}
