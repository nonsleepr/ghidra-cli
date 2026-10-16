//! Deterministic stripped ELF fixture: no compiler, proprietary data, or analyzer needed.
use serde_json::Value;
use std::path::PathBuf;
#[path = "fixtures/discovery_fixture.rs"]
mod fixture;
#[macro_use]
mod common;

struct Probe {
    _directory: tempfile::TempDir,
    project: PathBuf,
}
impl Probe {
    fn new() -> Self {
        Self::new_variant(false)
    }
    fn new_variant(big_endian: bool) -> Self {
        require_ghidra!();
        let directory = tempfile::Builder::new()
            .prefix("ghidra-discovery-")
            .tempdir()
            .unwrap();
        let binary = directory.path().join("discovery.elf");
        fixture::write(&binary, big_endian);
        let install = ghidra_cli::config::Config::load()
            .unwrap()
            .get_ghidra_install_dir()
            .unwrap();
        let headless = ghidra_cli::ghidra::bridge::find_headless_script(&install).unwrap();
        let output = std::process::Command::new(headless)
            .arg(directory.path())
            .arg("probe")
            .arg("-import")
            .arg(&binary)
            .arg("-noanalysis")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let project = directory.path().join("probe");
        Self {
            _directory: directory,
            project,
        }
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .arg("--json")
            .args(args)
            .arg("--project")
            .arg(&self.project)
            .args(["--program", "discovery.elf"])
            .output()
            .unwrap()
    }
    fn ok(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: {e}: {}", String::from_utf8_lossy(&out.stdout)))
    }
    fn java(&self, code: &str) -> String {
        self.ok(&["script", "java", code])["stdout"]
            .as_str()
            .unwrap()
            .trim()
            .to_string()
    }
    fn unchanged_marker(&self) -> String {
        self.java("println(Long.toString(currentProgram.getModificationNumber())); println(Long.toString(currentProgram.getListing().getNumInstructions())); println(Long.toString(currentProgram.getReferenceManager().getReferenceCountTo(toAddr(0x402000L))));")
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args(["stop", "--project"])
            .arg(&self.project)
            .output();
    }
}

#[test]
#[serial_test::serial]
fn discovery_on_unanalyzed_elf_is_bounded_and_read_only() {
    let p = Probe::new();
    let before = p.unchanged_marker();
    let strings = p.ok(&["find", "string", "DISCOVERYNEEDLE", "--details"]);
    assert_eq!(strings["count"], 3);
    assert_eq!(strings["search"]["truncated"], false);
    assert!(strings["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["value"] == "another discoveryneedle café"));
    assert_eq!(strings["results"][0]["address"], "00402000");
    assert_eq!(
        p.ok(&[
            "find",
            "string",
            "DISCOVERYNEEDLE",
            "--case-sensitive",
            "--details"
        ])["count"],
        0
    );
    assert_eq!(p.ok(&["strings", "refs", "DiscoveryNeedle"])["count"], 0);
    let found = p.ok(&[
        "strings",
        "refs",
        "DiscoveryNeedle",
        "--discover",
        "--start",
        "0x401000",
        "--end",
        "0x40103f",
    ]);
    let rows = found["results"].as_array().unwrap();
    let rows: Vec<_> = rows
        .iter()
        .filter(|v| v["reference_source"] == "decoded")
        .collect();
    assert_eq!(rows.len(), 3, "{found}");
    assert!(rows.iter().any(|v| v["from_function"].is_null()), "{found}");
    assert!(rows
        .iter()
        .filter(|v| v["from_function"].is_null())
        .all(|v| v["ownership"] == "unknown-no-containing-function"));
    assert!(rows.iter().any(|v| v["interior_offset"] == 7));
    assert_eq!(found["discovery"]["truncated"], false);
    let bounded = p.ok(&[
        "strings",
        "refs",
        "DiscoveryNeedle",
        "--discover",
        "--start",
        "0x401000",
        "--end",
        "0x40103f",
        "--scan-bytes",
        "7",
    ]);
    assert!(bounded["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["from"] == "00401000"));
    assert_eq!(bounded["discovery"]["truncated"], true);
    let output = p.run(&[
        "disasm",
        "0x401000",
        "-n",
        "1",
        "--resolve-strings",
        "--discover",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let instruction: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        instruction["references"][0]["string_preview"]["value"],
        "Prefix DiscoveryNeedle Tail"
    );
    assert_eq!(instruction["references"][0]["reference_source"], "decoded");
    let candidate = p.ok(&["function", "candidates", "--address", "0x401003"]);
    assert_eq!(candidate["count"], 1, "{candidate}");
    assert_eq!(candidate["results"][0]["range_end_exclusive"], "00401008");
    assert_eq!(candidate["results"][0]["next_indexed_start"], "00401020");
    assert_eq!(
        p.ok(&["function", "candidates", "--address", "0x401010"])["count"],
        0
    );
    assert_eq!(
        p.ok(&["function", "candidates", "--limit", "1"])["truncated"],
        true
    );
    let table = p.ok(&["vtable", "inspect", "0x405050", "--slots", "5"]);
    assert_eq!(table["typeinfo_name"], "12FixtureClass");
    assert_eq!(table["slots"].as_array().unwrap().len(), 5);
    assert_eq!(table["slots"][2]["status"], "null");
    assert_eq!(table["slots"][4]["status"], "unmapped");
    assert_eq!(
        p.ok(&["vtable", "inspect", "0x405090", "--slots", "1"])["offset_to_top"],
        -16
    );
    assert_eq!(
        p.unchanged_marker(),
        before,
        "Discovery changed the program"
    );

    assert!(assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["stop", "--project"])
        .arg(&p.project)
        .output()
        .unwrap()
        .status
        .success());
    assert_eq!(p.java("println(String.valueOf(getInstructionAt(toAddr(0x401010L)))); println(String.valueOf(getDataAt(toAddr(0x402040L))));"), "null\nnull");

    // Explicitly define just one duplicate; raw and defined results must merge.
    p.java("createAsciiString(toAddr(0x402000L));");
    let mixed = p.ok(&["find", "string", "discoveryneedle", "--details"]);
    assert_eq!(mixed["count"], 3);
    assert_eq!(mixed["results"][0]["source"], "defined");
    let legacy = p.run(&["find", "string", "discoveryneedle"]);
    assert!(legacy.status.success());
    assert_eq!(
        String::from_utf8_lossy(&legacy.stdout)
            .lines()
            .filter(|s| !s.trim().is_empty())
            .count(),
        3
    );
    assert_eq!(
        p.ok(&[
            "find",
            "string",
            "discoveryneedle",
            "--details",
            "--limit",
            "1"
        ])["search"]["truncated"],
        true
    );

    // Add one recorded reference, then ensure discovery deduplicates it.
    p.java("currentProgram.getReferenceManager().addMemoryReference(toAddr(0x401000L), toAddr(0x402000L), ghidra.program.model.symbol.RefType.DATA, ghidra.program.model.symbol.SourceType.USER_DEFINED, 1);");
    assert!(
        p.ok(&["strings", "refs", "DiscoveryNeedle"])["count"]
            .as_u64()
            .unwrap()
            >= 1
    );
    let mixed_refs = p.ok(&[
        "strings",
        "refs",
        "DiscoveryNeedle",
        "--discover",
        "--start",
        "0x401000",
        "--end",
        "0x40103f",
    ]);
    assert_eq!(
        mixed_refs["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["from"].as_str().is_some_and(|s| !s.contains("::")))
            .count(),
        3
    );
    assert_eq!(mixed_refs["results"][0]["reference_source"], "recorded");

    // Corruption is an explicit error, not a guessed range or a bridge crash.
    p.java("setByte(toAddr(0x404003L), (byte)0x77);");
    assert!(!p.run(&["function", "candidates"]).status.success());
    p.java("setByte(toAddr(0x404003L), (byte)0x3b); currentProgram.setImageBase(currentProgram.getImageBase().add(0x100000L), true);");
    let rebased = p.ok(&["function", "candidates", "--address", "0x501003"]);
    assert_eq!(
        rebased["results"][0]["range_start"], "00501000",
        "{rebased}"
    );
    assert_eq!(rebased["results"][0]["range_end_exclusive"], "00501008");
    let rebased_refs = p.ok(&[
        "strings",
        "refs",
        "DiscoveryNeedle",
        "--discover",
        "--start",
        "0x501000",
        "--end",
        "0x50103f",
    ]);
    assert_eq!(
        rebased_refs["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["from"].as_str().is_some_and(|s| !s.contains("::")))
            .count(),
        3
    );
    assert!(!p
        .run(&[
            "strings",
            "refs",
            "x",
            "--discover",
            "--start",
            "0x501040",
            "--end",
            "0x501000"
        ])
        .status
        .success());
    assert!(!p
        .run(&["vtable", "inspect", "0xdead0000", "--slots", "1"])
        .status
        .success());
    assert!(p.ok(&["program", "info"])["name"].is_string());
    p.java(r#"setBytes(toAddr(0x5020a0L), "WideNeedle".getBytes(java.nio.charset.StandardCharsets.UTF_16LE)); currentProgram.getListing().createData(toAddr(0x5020a0L), new ghidra.program.model.data.UnicodeDataType(), 22);"#);
    let wide = p.ok(&["find", "string", "WideNeedle", "--details"]);
    assert_eq!(wide["count"], 1);
    assert!(wide["results"][0]["encoding"]
        .as_str()
        .unwrap()
        .starts_with("UTF-16"));
    p.java("currentProgram.getMemory().createInitializedBlock(\"LongUtf8\", toAddr(0x506000L), 5000L, (byte)65, monitor, false);");
    let long = p.ok(&["find", "string", "missing-pattern", "--details"]);
    assert_eq!(long["count"], 0);
    assert_eq!(
        long["search"]["truncated"], true,
        "Long unsearched tails must be reported"
    );
}

#[test]
#[serial_test::serial]
fn unwind_endianness_encodings_absence_and_unsupported_discovery() {
    let p = Probe::new_variant(true);
    let found = p.ok(&["function", "candidates", "--address", "0x401003"]);
    assert_eq!(
        found["results"][0]["range_end_exclusive"], "00401008",
        "{found}"
    );
    assert_eq!(
        p.ok(&["vtable", "inspect", "0x405090", "--slots", "1"])["offset_to_top"],
        -16
    );
    let unsupported = p.run(&["strings", "refs", "Needle", "--discover"]);
    assert!(!unsupported.status.success());
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("x86-64"));
    // Same index using ULEB128 count and data-relative signed 16-bit entries.
    p.java("setByte(toAddr(0x404002L), (byte)1); setByte(toAddr(0x404003L), (byte)0x3a); setByte(toAddr(0x404008L), (byte)2); setShort(toAddr(0x404009L), (short)-0x3000); setShort(toAddr(0x40400bL), (short)-0xfec); setShort(toAddr(0x40400dL), (short)-0x2fe0); setShort(toAddr(0x40400fL), (short)-0xfd8);");
    let short = p.ok(&["function", "candidates", "--address", "0x401023"]);
    assert_eq!(
        short["results"][0]["range_end_exclusive"], "00401028",
        "{short}"
    );
    // Reject an unsupported CIE encoding without inventing a range end.
    p.java("setByte(toAddr(0x403010L), (byte)0x77);");
    let unsupported = p.ok(&["function", "candidates", "--address", "0x401000"]);
    assert!(unsupported["results"][0]["range_error"].is_string());
    assert!(unsupported["results"][0]["range_end_exclusive"].is_null());
    p.java(
        r#"currentProgram.getMemory().getBlock(".eh_frame_hdr").setName("renamed-unwind-header");"#,
    );
    let absent = p.ok(&["function", "candidates"]);
    assert_eq!(absent["available"], false);
    assert_eq!(absent["count"], 0);
}

impl Probe {
    fn status(&self) -> Value {
        let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args(["status", "--json", "--project"])
            .arg(&self.project)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
    fn stop(&self) {
        assert!(assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
            .args(["stop", "--project"])
            .arg(&self.project)
            .output()
            .unwrap()
            .status
            .success());
    }
}

#[test]
#[serial_test::serial]
fn identities_and_repeated_queries_reuse_one_bridge() {
    let p = Probe::new();
    let stopped = p.status();
    assert_eq!(stopped["state"], "stopped");
    assert_eq!(stopped["bridge"], Value::Null);
    p.ok(&["program", "info"]);
    let initial = p.status();
    assert_eq!(initial["state"], "running");
    assert_eq!(initial["compatibility"]["protocol"], "match");
    assert_eq!(initial["compatibility"]["script"], "match");
    assert_eq!(initial["pid"], initial["bridge"]["pid"]);
    assert_eq!(
        initial["client"]["build_id"],
        initial["bridge"]["cli_build_id"]
    );
    assert_eq!(
        initial["canonical_project"],
        initial["bridge"]["project_path"]
    );
    assert!(initial["bridge"]["java_version"].is_string());
    assert!(initial["bridge"]["ghidra_version"].is_string());
    let before = p.unchanged_marker();
    for _ in 0..3 {
        p.ok(&["find", "string", "DiscoveryNeedle", "--details"]);
        let current = p.status();
        assert_eq!(current["pid"], initial["pid"]);
        assert_eq!(current["port"], initial["port"]);
        assert_eq!(current["project_key"], initial["project_key"]);
        assert!(
            current["bridge"]["uptime_ms"].as_u64().unwrap()
                >= initial["bridge"]["uptime_ms"].as_u64().unwrap()
        );
    }
    assert_eq!(p.unchanged_marker(), before);
    p.stop();
    assert_eq!(p.status()["state"], "stopped");
}

#[test]
#[serial_test::serial]
fn prepared_function_signature_readback_and_reopen() {
    let p = Probe::new();
    // This entry has bytes but no persistent disassembly.
    assert_eq!(
        p.java("println(String.valueOf(getInstructionAt(toAddr(0x401010L))));"),
        "null"
    );
    let ordinary = p.run(&["function", "create", "0x401010", "prepared_fixture"]);
    eprintln!(
        "Unprepared create: success={} stderr={}",
        ordinary.status.success(),
        String::from_utf8_lossy(&ordinary.stderr)
    );
    assert!(!ordinary.status.success());
    assert!(String::from_utf8_lossy(&ordinary.stderr).contains("Failed to create function"));
    assert!(String::from_utf8_lossy(&ordinary.stderr).contains("function prepare"));
    assert_eq!(
        p.java("println(String.valueOf(getFunctionAt(toAddr(0x401010L))));"),
        "null"
    );
    let preparation = p.ok(&[
        "function",
        "prepare",
        "0x401010",
        "prepared_fixture",
        "--max-bytes",
        "8",
    ]);
    assert_eq!(preparation["status"], "prepared");
    assert_eq!(preparation["new_instruction_count"], 2);
    assert_eq!(preparation["total_size"], 8);
    assert_eq!(preparation["analysis_run"], false);
    assert_eq!(preparation["ranges"][0]["min_address"], "00401010");
    assert_eq!(preparation["ranges"][0]["max_address"], "00401017");
    assert_eq!(
        p.ok(&["function", "body", "0x401010"])["ranges"],
        preparation["ranges"]
    );
    assert_eq!(
        p.java("println(String.valueOf(getInstructionAt(toAddr(0x401018L))));"),
        "null"
    );
    let prepared = p.ok(&["function", "get", "0x401010"]);
    assert_eq!(prepared["name"], "prepared_fixture");
    p.ok(&["decompile", "0x401010"]);
    // Match the saved discrepancy's unusual starting state without touching its project.
    p.java("var f = getFunctionAt(toAddr(0x401010L)); f.setCallingConvention(ghidra.program.model.listing.Function.UNKNOWN_CALLING_CONVENTION_STRING); f.setCustomVariableStorage(true);");
    let edited = p.ok(&[
        "function",
        "set-signature",
        "0x401010",
        "--signature",
        "bool prepared_fixture(char *secret, char *key)",
    ]);
    let readback = p.ok(&["function", "get", "0x401010"]);
    assert_eq!(
        readback["signature"], edited["signature"],
        "{edited} {readback}"
    );
    assert!(
        readback["signature"].as_str().unwrap().contains("secret"),
        "{readback}"
    );
    assert!(
        readback["signature"].as_str().unwrap().contains("key"),
        "{readback}"
    );
    p.ok(&["decompile", "0x401010"]);
    assert_eq!(
        p.ok(&["function", "get", "0x401010"])["signature"],
        edited["signature"]
    );
    p.stop();
    assert_eq!(
        p.ok(&["function", "get", "0x401010"])["signature"],
        edited["signature"]
    );
    eprintln!("Prepared signature persisted: {}", edited["signature"]);
}

impl Probe {
    fn preparation_state(&self) -> String {
        self.java("println(Long.toString(currentProgram.getListing().getNumInstructions())); println(Long.toString(currentProgram.getFunctionManager().getFunctionCount())); println(Long.toString(currentProgram.getSymbolTable().getNumSymbols())); println(Long.toString(currentProgram.getBookmarkManager().getBookmarkCount())); int refs = 0; var it = currentProgram.getReferenceManager().getReferenceIterator(currentProgram.getMinAddress()); while (it.hasNext()) { it.next(); refs++; } println(Long.toString(refs));")
    }
    fn prepare_fails_without_changes(&self, args: &[&str], reason: &str) {
        let before = self.preparation_state();
        let output = self.run(args);
        assert!(!output.status.success(), "{args:?} unexpectedly succeeded");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(reason),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            self.preparation_state(),
            before,
            "Failed preparation changed metadata: {args:?}"
        );
    }
}

#[test]
#[serial_test::serial]
fn preparation_bounds_conflicts_and_failures_roll_back() {
    let p = Probe::new();
    p.prepare_fails_without_changes(&["function", "prepare", "0x401010"], "required");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "0"],
        "invalid value",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "1048577"],
        "invalid value",
    );
    p.prepare_fails_without_changes(
        &[
            "function",
            "prepare",
            "0x401010",
            "--end",
            "0x401017",
            "--max-bytes",
            "8",
        ],
        "cannot be used",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--end", "0x401000"],
        "End must",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--end", "0x601010"],
        "exceeds 1 MiB",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0xdead0000", "--max-bytes", "8"],
        "loaded and initialized",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x402000", "--max-bytes", "8"],
        "non-executable",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401000", "--max-bytes", "8"],
        "overlaps existing function",
    );
    // Both failures occur after persistent decoding started. Bytes, references,
    // symbols and disassembler error bookmarks must survive rollback unchanged.
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "6"],
        "crosses preparation boundary",
    );
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "7"],
        "escapes preparation window",
    );
    p.prepare_fails_without_changes(
        &[
            "function",
            "prepare",
            "0x401010",
            "bad\nname",
            "--max-bytes",
            "8",
        ],
        "no changes committed",
    );
    p.java("createData(toAddr(0x401013L), ghidra.program.model.data.ByteDataType.dataType);");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "8"],
        "overlaps defined data",
    );
    p.java("clearListing(toAddr(0x401013L), toAddr(0x401013L)); setBytes(toAddr(0x401010L), new byte[]{(byte)0xe9, 0x1b, 0, 0, 0});");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "8"],
        "escapes preparation window",
    );
    assert_eq!(
        p.java("println(String.valueOf(getInstructionAt(toAddr(0x401030L))));"),
        "null"
    );
    p.java("setBytes(toAddr(0x401010L), new byte[]{(byte)0xff, (byte)0xe0});");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "2"],
        "Unresolved jump",
    );
    p.java("setBytes(toAddr(0x401010L), new byte[]{(byte)0x90, (byte)0xc4, 0});");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "3"],
        "Cannot decode instruction",
    );
    assert_eq!(p.java("println(String.valueOf(getInstructionAt(toAddr(0x401010L)))); println(String.valueOf(getFunctionAt(toAddr(0x401010L))));"), "null\nnull");
    p.stop();
    assert_eq!(p.java("println(String.valueOf(getInstructionAt(toAddr(0x401010L)))); println(String.valueOf(getFunctionAt(toAddr(0x401010L))));"), "null\nnull");
}

#[test]
#[serial_test::serial]
fn preparation_reports_actual_ranges_skips_callees_and_reuses_instructions() {
    let p = Probe::new();
    p.java("disassemble(toAddr(0x401010L));");
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401011", "--max-bytes", "7"],
        "inside an existing instruction",
    );
    let reused = p.ok(&[
        "function",
        "prepare",
        "0x401010",
        "reused_fixture",
        "--end",
        "0x401017",
    ]);
    assert_eq!(reused["new_instruction_count"], 0);
    assert_eq!(reused["reused_instruction_count"], 2);
    p.prepare_fails_without_changes(
        &["function", "prepare", "0x401010", "--max-bytes", "8"],
        "overlaps existing function",
    );
    // CALL and RET lie in the body, but a callee inside the allowed window does not.
    p.java("currentProgram.getFunctionManager().removeFunction(toAddr(0x401010L)); clearListing(toAddr(0x401010L), toAddr(0x401017L)); setBytes(toAddr(0x401010L), new byte[]{(byte)0xe8, 0x0b, 0, 0, 0, (byte)0xc3});");
    let call = p.ok(&[
        "function",
        "prepare",
        "0x401010",
        "caller_fixture",
        "--max-bytes",
        "24",
    ]);
    assert_eq!(call["total_size"], 6);
    assert_eq!(call["new_instruction_count"], 2);
    assert_eq!(call["ranges"][0]["max_address"], "00401015");
    assert_eq!(p.java("println(String.valueOf(getInstructionAt(toAddr(0x401020L)))); println(String.valueOf(getFunctionAt(toAddr(0x401020L))));"), "null\nnull");
    // A direct branch can yield a disjoint body; the bound is not the body.
    p.java("currentProgram.getFunctionManager().removeFunction(toAddr(0x401010L)); clearListing(toAddr(0x401010L), toAddr(0x401017L)); setBytes(toAddr(0x401010L), new byte[]{(byte)0xeb, 6}); setByte(toAddr(0x401018L), (byte)0xc3);");
    let split = p.ok(&[
        "function",
        "prepare",
        "0x401010",
        "split_fixture",
        "--end",
        "0x401018",
    ]);
    assert_eq!(split["total_size"], 3);
    assert_eq!(split["range_count"], 2);
    assert_eq!(split["is_contiguous"], false);
    assert_eq!(
        p.java("println(String.valueOf(getInstructionAt(toAddr(0x401012L))));"),
        "null"
    );
    let independent = p.ok(&["function", "body", "0x401010"]);
    assert_eq!(independent["ranges"], split["ranges"]);
    p.stop();
    assert_eq!(
        p.ok(&["function", "body", "0x401010"])["ranges"],
        split["ranges"]
    );
    // Visit both conditional paths, and terminate a closed loop without filling gaps.
    p.java("currentProgram.getFunctionManager().removeFunction(toAddr(0x401010L)); clearListing(toAddr(0x401010L), toAddr(0x401018L)); setBytes(toAddr(0x401010L), new byte[]{0x75, 2, (byte)0x90, (byte)0xc3, (byte)0xc3});");
    let conditional = p.ok(&["function", "prepare", "0x401010", "--max-bytes", "5"]);
    assert_eq!(conditional["total_size"], 5);
    assert_eq!(conditional["new_instruction_count"], 4);
    p.java("currentProgram.getFunctionManager().removeFunction(toAddr(0x401010L)); clearListing(toAddr(0x401010L), toAddr(0x401014L)); setBytes(toAddr(0x401010L), new byte[]{(byte)0xeb, (byte)0xfe});");
    let looping = p.ok(&["function", "prepare", "0x401010", "--max-bytes", "2"]);
    assert_eq!(looping["total_size"], 2);
    assert_eq!(looping["new_instruction_count"], 1);
}
