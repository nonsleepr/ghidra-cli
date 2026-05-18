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

For full documentation, run:

```
man ghidra-cli
```

or use the `--help` / `<subcommand> --help` flags.

If `man ghidra-cli` is not available (package not installed globally), see `SKILL.fallback.md`
in this directory — it is auto-generated from `docs/ghidra-cli.1` by `build.rs` on every build.
