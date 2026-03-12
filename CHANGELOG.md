# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Type system enhancements**:
  - `type delete` / `type rename` - CRUD completion for data types
  - `type create-enum` - Create enum types with `--values "KEY=VAL,..."` and `--size`
  - `type typedef` - Create typedef aliases
  - `type add-field` / `type del-field` - Add/remove struct fields with offset and size control
  - `type list` now includes `kind` field (struct/union/enum/typedef/pointer/array/other)
  - `type get` now shows enum members, typedef base type, and `kind` on all types
- **Function signature editing**:
  - `function set-signature` - Set full C-style function signature (parsed by Ghidra's CParser)
  - `function set-return-type` - Set function return type
  - `function set-calling-convention` - Set calling convention (__cdecl, __stdcall, etc.)
  - `function set-var-type` - Retype local variables and parameters in decompiled functions
- **Structured decompile output**:
  - `decompile --with-vars` - Include local variable details (name, type, storage)
  - `decompile --with-params` - Include parameter details (name, type, storage)
- **Internal**: `resolveDataType()` helper in Java bridge for unified type resolution with pointer syntax support

### Changed

- **BREAKING**: Replaced Python bridge (`bridge.py`) with Java bridge (`GhidraCliBridge.java`)
  - Architecture simplified from 3 layers (CLI → Rust daemon → Python bridge) to 2 layers (CLI → Java bridge)
  - No separate Rust daemon process — CLI connects directly to Java bridge via TCP
  - Bridge runs as a GhidraScript inside `analyzeHeadless` JVM
  - Dynamic port binding with port/PID file discovery (`~/.local/share/ghidra-cli/bridge-{hash}.port`)
- **BREAKING**: Removed Python/PyGhidra dependency — only Java 17+ and Ghidra are required
- `ghidra setup` no longer installs PyGhidra
- `ghidra doctor` no longer checks for Python/PyGhidra

### Removed

- All 13 Python scripts (`bridge.py`, `find.py`, `symbols.py`, `types.py`, `comments.py`, `graph.py`, `diff.py`, `patch.py`, `disasm.py`, `stats.py`, `program.py`, `script_runner.py`, `batch.py`)
- Rust daemon process and associated modules (`handler.rs`, `handlers/`, `ipc_server.rs`, `process.rs`, `queue.rs`, `state.rs`, `cache.rs`)
- Dependencies: `remoc`, `interprocess`, `fslock`
- Unix domain socket IPC — replaced with direct TCP to Java bridge

### Security

- Local TCP communication only (localhost binding, no external access)

## [0.1.0] - 2025-01-26

### Added

- Daemon-only architecture with persistent Ghidra connection
- Auto-start daemon on import/analyze/quick commands
- Comprehensive reverse engineering commands:
  - Function analysis (list, decompile, disassemble, calls, xrefs)
  - Symbol management (list, get, create, delete, rename)
  - String analysis and search
  - Type definitions and application
  - Comment management
  - Memory operations
  - Cross-reference analysis
- Search capabilities:
  - String patterns
  - Byte sequences
  - Function names
  - Crypto constants
  - Interesting patterns
- Call graph generation and export
- Binary patching (bytes, NOP, export)
- Script execution (Python and Java)
- Batch operations
- Flexible output formats:
  - Human-readable (default for TTY)
  - Compact JSON (default for pipes)
  - Pretty JSON (--pretty flag)
- Expression-based filtering
- AI agent integration support

### Security

- Local IPC communication only (Unix sockets / named pipes)

[unreleased]: https://github.com/akiselev/ghidra-cli/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/akiselev/ghidra-cli/releases/tag/v0.1.0
