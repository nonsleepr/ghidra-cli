# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] - 2026-03-11

### Added

- **Type system**:
  - `type delete` / `type rename` — CRUD completion for data types
  - `type create-enum` — create enum types with `--values "KEY=VAL,..."` and `--size`
  - `type typedef` — create typedef aliases
  - `type add-field` / `type del-field` — add/remove struct fields with offset and size control
  - `type list` now includes `kind` field (struct/union/enum/typedef/pointer/array/other)
  - `type get` now shows enum members, typedef base type, and `kind` on all types
- **Function signature editing**:
  - `function set-signature` — set full C-style function signature (parsed by Ghidra's CParser)
  - `function set-return-type` — set function return type
  - `function set-calling-convention` — set calling convention (`__cdecl`, `__stdcall`, etc.)
  - `function set-var-type` — retype local variables and parameters in decompiled functions
- **Structured decompile output**:
  - `decompile --with-vars` — include local variable details (name, type, storage)
  - `decompile --with-params` — include parameter details (name, type, storage)
- `resolveDataType()` helper in Java bridge — unified type resolution with pointer syntax support
- Nix flake with auto-configured `GHIDRA_INSTALL_DIR` and Java in PATH

### Fixed

- **B-1**: `function calls`/`callers`/`callees` returned empty results (wrong bridge command names)
- **B-2**: `strings refs` returned no cross-references (filter applied before address lookup)
- **B-3**: `patch bytes` failed on write-protected memory (transaction missing `setMemoryWritable`)
- **B-4**: `dump imports`/`dump exports` ignored `--limit` (limit applied after serialisation)
- **B-5**: `comment list` omitted user-set comments in large binaries — two causes: `listing.getComment()` unreliable for instruction addresses (use `getCodeUnitAt().getComment()`); `default_limit: 1000` truncated output before user-set comments appeared. Fix: use `getCommentAddressIterator`; `comment list` no longer applies `default_limit`

### Changed

- **BREAKING**: Replaced Python bridge (`bridge.py` + 12 category scripts) with a single Java bridge (`GhidraCliBridge.java`)
  - Architecture simplified from 3 layers (CLI → Rust daemon → Python) to 2 layers (CLI → Java bridge)
  - No separate Rust daemon process — CLI connects directly to Java bridge via TCP
  - Bridge runs as a `GhidraScript` inside `analyzeHeadless` JVM
  - Dynamic port binding with port/PID file discovery (`~/.local/share/ghidra-cli/bridge-{hash}.port`)
- **BREAKING**: Removed Python/PyGhidra dependency — only Java 17+ and Ghidra 12+ are required
- `ghidra setup` no longer installs PyGhidra
- `ghidra doctor` no longer checks for Python/PyGhidra
- All deprecated Ghidra 12 integer comment-type constants replaced with `CommentType` enum

### Removed

- All Python scripts (`bridge.py`, `find.py`, `symbols.py`, `types.py`, `comments.py`, `graph.py`, `diff.py`, `patch.py`, `disasm.py`, `stats.py`, `program.py`, `script_runner.py`, `batch.py`)
- Rust daemon process and associated modules
- Unix domain socket IPC — replaced with direct TCP to Java bridge

### Security

- Local TCP communication only (localhost binding, no external access)

## [0.1.0] - 2025-01-26

### Added

- Initial release: daemon-based architecture with persistent Ghidra connection
- Comprehensive reverse engineering commands: functions, symbols, strings, types, comments, memory, xrefs, call graphs, patching, scripts, batch
- Expression-based filtering, multiple output formats (human-readable, JSON, CSV)
- AI agent integration support

[0.1.10]: https://github.com/nonsleepr/ghidra-cli/compare/v0.1.0...v0.1.10
[0.1.0]: https://github.com/nonsleepr/ghidra-cli/releases/tag/v0.1.0
