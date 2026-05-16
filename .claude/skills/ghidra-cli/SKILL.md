---
name: ghidra-cli
description: >
    Use ghidra-cli for reverse engineering tasks: binary analysis, decompilation, function inspection, cross-reference analysis, pattern discovery, binary patching, and type system management.
    Activate when the user requests:
    - Binary analysis or reverse engineering
    - Decompilation or disassembly
    - Function listing, inspection, or renaming
    - Cross-reference or call graph analysis
    - String or byte pattern searches
    - Binary patching or modification
    - Ghidra project management
    - Type management (structs, enums, typedefs, struct fields)
    - Function signature editing (return type, calling convention, full signature)
    - Variable retyping in decompiled functions
---

# ghidra-cli Agent Reference

Rust CLI for Ghidra reverse engineering. Binary name: `ghidra-cli`.

For exact flag syntax, run: `ghidra-cli --help` or `ghidra-cli <command> --help`

## Architecture

```
CLI (Rust/clap) ──TCP──► GhidraCliBridge.java (GhidraScript in Ghidra JVM)
```

- **No daemon**: the Java bridge IS the persistent server, auto-started on first use.
- One bridge per project, keyed by `~/.local/share/ghidra-cli/bridge-{md5}.port`
- Sequential command processing (Ghidra API is not thread-safe)

## Output Formats (`-o FORMAT`)

| Value | Use |
|-------|-----|
| `compact` | Default for TTY. One line per item. |
| `full` | Multi-line labeled blocks |
| `json` | Pretty JSON |
| `json-compact` | Default for pipes. Single-line JSON. |
| `json-stream` / `ndjson` | One JSON object per line |
| `csv` / `tsv` | Delimited with header |
| `table` | ASCII box-drawn table |
| `count` | Number only |
| `ids` / `minimal` | Address/name only, one per line |
| `tree` | Indented hierarchy |
| `hex` | Hex dump |
| `asm` | Assembly |
| `c` | C pseudocode |

**Auto-detection**: TTY → `compact`; pipe → `json-compact`. Override with `--json`, `--pretty`, or `-o FORMAT`.

## Filter Expressions (`--filter EXPR`)

```bash
--filter "size > 100"
--filter "name ~ 'crypt'"
--filter "size > 100 AND name ~ 'main'"
```

Operators: `=`, `!=`, `>`, `>=`, `<`, `<=`, `~` (contains), `^` (starts with), `$` (ends with), `=~` (regex), `AND`, `OR`, `NOT`, `IN`, `EXISTS`.

## Program Selection

No `default_program` config. Bridge selects program as follows:
1. `--program NAME` given → use it directly.
2. No `--program` → scan `<project>.rep/idata/00/*.prp` locally:
   - Exactly 1 program → auto-select.
   - Multiple → error listing all names; user must add `--program`.

`set-default project` sets the default project. `set-default program` is intentionally absent.

## Agent Best Practices

### Count-First
```bash
ghidra-cli function list --count --project P
ghidra-cli function list --limit 50 --fields name,address,size --project P
```

### Server-Side Filtering
```bash
# Good: filter in bridge
ghidra-cli function list --filter "size > 1000" --project P
# Bad: fetch all, filter in agent
ghidra-cli function list --project P
```

### Field Selection
```bash
ghidra-cli function list --fields name,address --json --project P
```

## Analysis Workflow

```bash
# 1. Import and analyze
ghidra-cli import ./target.exe --project analysis
ghidra-cli analyze --project analysis

# 2. Recon
ghidra-cli summary --project analysis
ghidra-cli function list --count --project analysis
ghidra-cli function list --filter "NOT name ^ 'FUN_'" --fields name,address,size --limit 30 --project analysis

# 3. Investigate
ghidra-cli decompile main --project analysis
ghidra-cli decompile main --with-vars --with-params --json --project analysis
ghidra-cli find crypto --project analysis
ghidra-cli find string "password" --project analysis

# 4. Deep dive
ghidra-cli graph callers suspicious_func --depth 3 --project analysis
ghidra-cli x-ref to 0x401000 --project analysis

# 5. Type annotation (improves decompile output)
ghidra-cli type create MyStruct --project analysis
ghidra-cli type add-field MyStruct --name fd --type int --project analysis
ghidra-cli type create-enum ErrorCode --values "OK=0,ENOENT=2,EPERM=1" --project analysis
ghidra-cli function set-signature parse_data --signature "int parse_data(char *buf, int len)" --project analysis
ghidra-cli function set-var-type main --var local_10 --type "MyStruct *" --project analysis
ghidra-cli decompile main --project analysis  # re-decompile with new types

# 6. Patch
ghidra-cli patch nop 0x401234 --count 3 --project analysis
ghidra-cli patch export -o patched.exe --project analysis
```

## Known Bugs / Limitations

- `x-ref list` ignores optional TARGET argument at runtime; always lists all xrefs.
- `patch nop --count N`: `--count` is parsed but not forwarded to bridge; only single-address NOP applied.
- `comment set --comment-type`: bridge expects `comment_type` key, client sends `type`; comment type falls back to `EOL` always.

## .NET Warning

`ghidra-cli decompile` emits a warning for .NET IL bytecode. Use `ilspy-cli` instead for .NET assemblies.

## Error Recovery

| Problem | Fix |
|---------|-----|
| "No project specified" | Add `--project NAME` or `ghidra-cli set-default project NAME` |
| "Bridge not responding" | `ghidra-cli stop --project P` then retry (auto-starts) |
| "Ghidra installation not configured" | `ghidra-cli setup` or set `GHIDRA_INSTALL_DIR` |
| Function not found | `ghidra-cli find function "*pattern*"` |
| Slow first command | Normal: bridge startup + analysis takes seconds |

## File Locations

| File | Purpose |
|------|---------|
| `~/.local/share/ghidra-cli/bridge-{md5}.port` | TCP port for running bridge |
| `~/.local/share/ghidra-cli/bridge-{md5}.pid` | Bridge PID |
| `~/.config/ghidra-cli/config.yaml` | Configuration |
| `~/.config/ghidra-cli/scripts/GhidraCliBridge.java` | Materialized Java bridge script |
| `~/.local/share/ghidra-cli/ghidra-cli.log` | Debug log |

