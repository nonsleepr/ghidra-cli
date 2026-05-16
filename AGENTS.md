# Agent Instructions

## Critical Rules

1. **NEVER SKIP TESTS.** `require_ghidra!()` panics when `ghidra doctor` fails — that is intentional. Tests must fail if Ghidra is not installed.
2. **Run tests with `--test-threads=1`** — OSGi cache contention between test suites causes failures with parallel threads.
3. **Never launch the `ghidra` Nix flake app from shell** — it starts the GUI. Use `./target/debug/ghidra-cli` for the CLI binary.
4. **Default output is human-readable, not JSON.** Use `--json` / `--pretty` flags. Exception: non-TTY stdout auto-detects to compact JSON (Unix pipe convention).

## Architecture

```
ghidra CLI (Rust/clap)
    │  TCP JSON-RPC (localhost, dynamic port)
    ▼
GhidraCliBridge.java  (GhidraScript running inside analyzeHeadless JVM)
    │  reads/writes
    ▼
Ghidra Project (~/.local/share/ghidra-projects/)
```

- **No daemon process.** The Java bridge IS the persistent server.
- **One bridge per project**, keyed by MD5 of project path → `~/.local/share/ghidra-cli/bridge-{md5}.port` / `.pid`
- **Bridge auto-starts** on import/analyze/query commands if not running.
- **Sequential command processing** — Ghidra `Program` objects are not thread-safe for writes.
- Bridge script is embedded via `include_str!` in `src/ghidra/bridge.rs` and written to `~/.config/ghidra-cli/scripts/GhidraCliBridge.java` on every bridge start. **Touch the `.java` file or edit `bridge.rs` to force Rust recompile.**

## Key Files

| File | What it does |
|------|-------------|
| `src/ghidra/scripts/GhidraCliBridge.java` | All bridge logic: TCP server, 40+ command handlers, Ghidra API calls |
| `src/main.rs` | CLI entry, bridge lifecycle orchestration, output format detection |
| `src/cli.rs` | clap CLI definition — all commands and flags |
| `src/ghidra/bridge.rs` | Bridge process management: start/stop/liveness; embeds Java script |
| `src/ipc/client.rs` | `BridgeClient` — single entry point for all TCP commands |
| `src/ipc/protocol.rs` | `BridgeRequest` / `BridgeResponse` wire format |
| `tests/common/mod.rs` | `DaemonTestHarness` — starts/stops bridge for test suites |
| `tests/common/helpers.rs` | `GhidraCommand` builder, `get_function_addresses` helper |

## Ghidra API Footguns

### `listing.getComment(type, addr)` is unreliable for instruction addresses
`CodeManager.getComment()` calls `addrMap.getKey(addr, false)` which returns an invalid key for instruction-mapped addresses — silently returns `null` even when a comment exists.

**Always use:**
```java
CodeUnit cu = currentProgram.getListing().getCodeUnitAt(addr);
if (cu != null) cu.getComment(CommentType.EOL);
```
Or for iteration: `listing.getCommentAddressIterator(memory, true)` — iterates via range scan on adapter records, reliable for all address types.

### `comment list` must not apply `default_limit`
Large binaries accumulate thousands of auto-generated LSDA/DWARF comments. Applying `default_limit: 1000` hides user-set comments that appear later in address order. Only explicit `--limit N` is honored for `comment list`.

### Write operations require transactions
Any handler that modifies program state must wrap in a transaction:
```java
int txId = currentProgram.startTransaction("description");
try { /* modify */ } finally { currentProgram.endTransaction(txId, true); }
```

### Patch writes require writable memory
Before `memory.setBytes()`, call `memory.setMemoryWritable(block, true)` and restore after. Without this, writes to read-only segments silently fail or throw.

### Deprecated comment-type constants
Use `CommentType.EOL`, `CommentType.PRE`, etc. — not the deprecated integer constants (`CodeUnit.EOL_COMMENT = 0`). Ghidra 12 removed the old constants.

## Bridge Lifecycle Details

### PID file written twice
1. Rust writes immediately after `child.spawn()` (OS PID) — enables orphan cleanup if Java crashes before binding.
2. Java overwrites once `ServerSocket` is bound — confirms bridge reached ready state.

### Liveness check order (`is_bridge_running`)
1. Port file exists and contains valid u16
2. PID file exists and contains valid u32
3. PID alive (`kill(pid, 0)` on Unix)
4. TCP connect to `127.0.0.1:{port}` succeeds

### Start modes
| Mode | `analyzeHeadless` args | When |
|------|----------------------|------|
| `Import { binary_path }` | `-import <path>` | First import of binary (auto-analyzes) |
| `Process { program_name }` | `-process <name> -noanalysis` | Open existing program for queries |

## Test Conventions

```bash
cargo test -- --test-threads=1
```

- Each test suite uses a unique `TEST_PROJECT` constant for its own bridge instance.
- `ensure_test_project(project, program)` is idempotent via `Once::call_once`.
- `require_ghidra!()` panics with doctor output if Ghidra unavailable — explicit failure, not silent skip.
- Tests within a suite are marked `#[serial]` to prevent bridge state races.
- **Test fixture**: `tests/fixtures/sample_binary` — compile with:
  ```bash
  rustc --edition 2021 -o tests/fixtures/sample_binary tests/fixtures/sample_binary.rs
  ```
  Functions: `add`, `multiply`, `factorial`, `fibonacci`, `process_string`, `xor_encrypt`, `simple_hash`, `init_data`, `main`.

### Adding a new command
1. Add variant to the appropriate enum in `src/cli.rs`
2. Add handler match arm in `src/main.rs`
3. Add typed method to `BridgeClient` in `src/ipc/client.rs`
4. Implement `handle*` method in `GhidraCliBridge.java`, add to `handleRequest()` dispatch
5. Add tests in the appropriate `tests/*_tests.rs` file

## Environment

| Variable | Purpose |
|----------|---------|
| `GHIDRA_INSTALL_DIR` | Ghidra installation path (auto-set by Nix flake) |
| `GHIDRA_PROJECT_DIR` | Base directory for projects |
| `GHIDRA_DEFAULT_PROJECT` | Default `--project` value |
| `GHIDRA_CLI_CONFIG` | Override config file path |

Config: `~/.config/ghidra-cli/config.yaml`
`default_limit: 1000` applies to function/string/symbol list commands. **Not** applied to `comment list`.

## Program selection

There is no `default_program` config key. The bridge selects the program as follows:

1. **`--program NAME` is given** → load that program directly.
2. **No `--program`** → read `<project>.rep/idata/00/*.prp` metadata locally (no bridge needed), then:
   - Exactly 1 program → auto-select it.
   - Multiple programs → error listing all names; user must add `--program`.
   - 0 programs → error "No programs found. Import a binary first."

`set-default program` is intentionally removed. `set-default project` still works.
