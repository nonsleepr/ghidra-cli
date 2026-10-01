//! Tests for function-mutation commands added alongside the verification-workflow
//! improvements: `function set-no-return`, `function body`, `function set-body`,
//! bounded `disasm` ranges (`--end`/`--bytes`), and decompiler warnings surfaced
//! in `decompile` output.

use serial_test::serial;
use std::sync::OnceLock;

#[macro_use]
mod common;
use common::{get_function_address, ghidra, schemas::Function, DaemonTestHarness};

/// Extract (address, bytes-length) pairs from disasm JSONL output.
///
/// The bridge's `operands` field is a JSON array of operand strings, which
/// doesn't match the shared `Instruction` schema's `operands: Option<String>`
/// (used by other, older tests) — so we parse disasm output as raw JSON here
/// rather than via that schema.
fn parse_disasm_instructions(result: &common::GhidraResult) -> Vec<serde_json::Value> {
    let trimmed = result.stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    // Try a single JSON value first (e.g. `{"instructions": [...], ...}`).
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(instrs) = value.get("instructions").and_then(|v| v.as_array()) {
            return instrs.clone();
        }
        if let serde_json::Value::Array(arr) = value {
            return arr;
        }
        return vec![value];
    }
    // Fall back to JSONL: one instruction object per line.
    trimmed
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

const TEST_PROJECT: &str = "ci-test-function-mutation";
const TEST_PROGRAM: &str = "sample_binary";

static HARNESS: OnceLock<DaemonTestHarness> = OnceLock::new();

fn harness() -> &'static DaemonTestHarness {
    HARNESS.get_or_init(|| {
        common::ensure_test_project(TEST_PROJECT, TEST_PROGRAM);
        DaemonTestHarness::new(TEST_PROJECT, TEST_PROGRAM).expect("Failed to start daemon")
    })
}

/// `function get` should report a `no_return` boolean field for every function,
/// defaulting to false for ordinary functions.
#[test]
#[serial]
fn test_function_get_reports_no_return_field() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("get")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();
    let func: Function = result.json();
    assert_eq!(
        func.no_return,
        Some(false),
        "main should not be marked no_return by default"
    );
}

/// `function set-no-return` should flip the flag, and the change should be
/// visible via a subsequent `function get`. Revert at the end so other tests
/// sharing this project see a clean function.
#[test]
#[serial]
fn test_function_set_no_return_roundtrip() {
    require_ghidra!();
    let harness = harness();

    // Use a small, rarely-referenced helper so we don't disturb other tests
    // relying on `main`'s normal behavior.
    let target = "factorial";

    let set_true = ghidra(harness)
        .arg("function")
        .arg("set-no-return")
        .arg(target)
        .arg("--no-return")
        .arg("true")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    set_true.assert_success();
    set_true.assert_stdout_contains("no_return_set");

    let get_after_set = ghidra(harness)
        .arg("function")
        .arg("get")
        .arg(target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    get_after_set.assert_success();
    let func: Function = get_after_set.json();
    assert_eq!(
        func.no_return,
        Some(true),
        "no_return should be true after set-no-return --no-return true"
    );

    // Revert.
    let set_false = ghidra(harness)
        .arg("function")
        .arg("set-no-return")
        .arg(target)
        .arg("--no-return")
        .arg("false")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    set_false.assert_success();

    let get_after_revert = ghidra(harness)
        .arg("function")
        .arg("get")
        .arg(target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    get_after_revert.assert_success();
    let func: Function = get_after_revert.json();
    assert_eq!(
        func.no_return,
        Some(false),
        "no_return should be false again after reverting"
    );
}

/// `function set-no-return` on an unknown target should fail gracefully.
#[test]
#[serial]
fn test_function_set_no_return_unknown_target_fails() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("set-no-return")
        .arg("this_function_does_not_exist_zzz")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_failure();
}

/// `function body` should return at least one address range covering the
/// function, with min/max addresses and a total size.
#[test]
#[serial]
fn test_function_body_returns_ranges() {
    require_ghidra!();
    let harness = harness();

    let result = ghidra(harness)
        .arg("function")
        .arg("body")
        .arg("main")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();
    let value: serde_json::Value = result.json();

    let ranges = value
        .get("ranges")
        .and_then(|v| v.as_array())
        .expect("expected a 'ranges' array in function body output");
    assert!(
        !ranges.is_empty(),
        "function body should report at least one address range"
    );
    for range in ranges {
        assert!(
            range.get("min_address").and_then(|v| v.as_str()).is_some(),
            "each range should have a min_address"
        );
        assert!(
            range.get("max_address").and_then(|v| v.as_str()).is_some(),
            "each range should have a max_address"
        );
    }
    assert!(
        value.get("total_size").and_then(|v| v.as_u64()).is_some(),
        "function body should report total_size"
    );
    assert!(
        value
            .get("is_contiguous")
            .and_then(|v| v.as_bool())
            .is_some(),
        "function body should report is_contiguous"
    );
}

/// `function set-body` should be able to shrink a function's body by removing
/// a trailing range, and `function body` should reflect the smaller size.
/// We use a small, rarely-referenced helper and restore the original body
/// afterwards so other tests aren't affected.
#[test]
#[serial]
fn test_function_set_body_shrink_and_restore() {
    require_ghidra!();
    let harness = harness();

    let target = "deregister_tm_clones";
    let addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, target);

    // Read original body/size so we can restore it afterward.
    let before = ghidra(harness)
        .arg("function")
        .arg("body")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    before.assert_success();
    let before_json: serde_json::Value = before.json();
    let original_size = before_json
        .get("total_size")
        .and_then(|v| v.as_u64())
        .expect("expected total_size in function body output");
    let ranges = before_json
        .get("ranges")
        .and_then(|v| v.as_array())
        .expect("expected ranges array");
    let last_range = ranges
        .last()
        .expect("function should have at least one range");
    let last_min = last_range
        .get("min_address")
        .and_then(|v| v.as_str())
        .expect("range should have min_address")
        .to_string();
    let last_max = last_range
        .get("max_address")
        .and_then(|v| v.as_str())
        .expect("range should have max_address")
        .to_string();

    // Remove the last range entirely.
    let remove = ghidra(harness)
        .arg("function")
        .arg("set-body")
        .arg(&addr)
        .arg("--start")
        .arg(&last_min)
        .arg("--end")
        .arg(&last_max)
        .arg("--action")
        .arg("remove")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    remove.assert_success();
    remove.assert_stdout_contains("body_set");

    let after_remove = ghidra(harness)
        .arg("function")
        .arg("body")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    after_remove.assert_success();
    let after_json: serde_json::Value = after_remove.json();
    let shrunk_size = after_json
        .get("total_size")
        .and_then(|v| v.as_u64())
        .expect("expected total_size after shrink");
    assert!(
        shrunk_size < original_size,
        "body should shrink after removing a range: {} should be < {}",
        shrunk_size,
        original_size
    );

    // Restore by adding the range back.
    let restore = ghidra(harness)
        .arg("function")
        .arg("set-body")
        .arg(&addr)
        .arg("--start")
        .arg(&last_min)
        .arg("--end")
        .arg(&last_max)
        .arg("--action")
        .arg("add")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    restore.assert_success();

    let after_restore = ghidra(harness)
        .arg("function")
        .arg("body")
        .arg(&addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    after_restore.assert_success();
    let restored_json: serde_json::Value = after_restore.json();
    let restored_size = restored_json
        .get("total_size")
        .and_then(|v| v.as_u64())
        .expect("expected total_size after restore");
    assert_eq!(
        restored_size, original_size,
        "body size should match original after restoring the removed range"
    );
}

/// `disasm --end` should stop at (and include) the instruction at the given
/// end address, bounding the output by address rather than instruction count.
#[test]
#[serial]
fn test_disasm_bounded_by_end_address() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    // First, grab a few instructions to find a valid "end" address partway through.
    let probe = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--instructions")
        .arg("4")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    probe.assert_success();
    let probe_instrs = parse_disasm_instructions(&probe);
    assert!(
        probe_instrs.len() >= 3,
        "need at least 3 instructions to test a bounded range, got {}",
        probe_instrs.len()
    );
    let end_addr = probe_instrs[2]
        .get("address")
        .and_then(|v| v.as_str())
        .expect("instruction should have an address field")
        .to_string();

    let bounded = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--end")
        .arg(&end_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    bounded.assert_success();
    let bounded_instrs = parse_disasm_instructions(&bounded);

    assert!(
        !bounded_instrs.is_empty(),
        "bounded disasm should return at least one instruction"
    );
    let last_addr = bounded_instrs
        .last()
        .unwrap()
        .get("address")
        .and_then(|v| v.as_str())
        .expect("last instruction should have an address field");
    assert_eq!(
        last_addr, end_addr,
        "last instruction address should match the requested --end address"
    );
}

/// `disasm --bytes` should stop once at least the requested number of bytes
/// have been consumed, rather than a fixed instruction count.
#[test]
#[serial]
fn test_disasm_bounded_by_bytes() {
    require_ghidra!();
    let harness = harness();

    let main_addr = get_function_address(harness, TEST_PROJECT, TEST_PROGRAM, "main");

    let result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .arg("--bytes")
        .arg("8")
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    result.assert_success();

    let instrs = parse_disasm_instructions(&result);
    assert!(
        !instrs.is_empty(),
        "bounded-by-bytes disasm should return at least one instruction"
    );

    // Without --bytes/--end, the default is 10 instructions; a small byte
    // budget should generally return fewer than that unless instructions are
    // unusually large.
    let default_result = ghidra(harness)
        .arg("disasm")
        .arg(&main_addr)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();
    default_result.assert_success();
    let default_instrs = parse_disasm_instructions(&default_result);

    assert!(
        instrs.len() <= default_instrs.len(),
        "a small --bytes budget should not return more instructions than the default count"
    );
}

/// `decompile` on a normal function should not include a spurious `warnings`
/// field when the decompiler completes cleanly.
#[test]
#[serial]
fn test_decompile_clean_function_has_no_warnings_field() {
    require_ghidra!();
    let harness = harness();

    let target = "factorial";
    let result = ghidra(harness)
        .arg("decompile")
        .arg(target)
        .with_project(TEST_PROJECT, TEST_PROGRAM)
        .json_format()
        .run();

    result.assert_success();
    let value: serde_json::Value = result.json();
    assert!(
        value.get("code").and_then(|v| v.as_str()).is_some(),
        "decompile output should include a code field"
    );
    // A simple recursive function like factorial should decompile cleanly
    // with no decompiler warnings.
    assert!(
        value.get("warnings").is_none(),
        "clean decompile should not include a warnings field, got: {:?}",
        value.get("warnings")
    );
}
