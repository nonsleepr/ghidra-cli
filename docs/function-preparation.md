# Bounded function preparation

`function prepare` persists disassembly and creates one function in a single
transaction. Use it when an imported program has code bytes but no instructions
or function metadata at a reviewed entry.

```sh
ghidra-cli function prepare 0x401010 selected_function --max-bytes 64 \
  --project PROJECT --program PROGRAM --json
ghidra-cli function prepare 0x401010 --end 0x40104f \
  --project PROJECT --program PROGRAM
```

The name is optional and positional, as with `function create`. Exactly one
explicit bound is required: `--max-bytes` starts at the entry; `--end` is
inclusive. The entire window must be loaded, initialized, executable memory in
one byte-addressable address space, with a maximum size of 1 MiB. The entry must
satisfy the program language's instruction alignment.

Preparation rejects any existing function or defined data overlapping the
window, even if unreachable from the entry. Existing instructions can be reused
when their starts and complete byte ranges fit. It does not clear data, replace
functions or change existing instruction boundaries. Choose a smaller window or
inspect a conflict explicitly rather than treating the command as an override.

The command walks Ghidra instruction fallthroughs and direct branches from the
entry. It does not follow calls into callees, including callees inside the
window, or fill unreachable gaps. Indirect calls can be retained; unresolved
jumps (including computed switches), delay-slot instructions, offcut targets,
undecodable instructions and any non-call flow escaping the window fail the
whole operation. A closed loop is allowed. Tail jumps outside the window are
rejected in this initial version.

Each persistent decode is limited to one instruction start with automatic code
analysis disabled. Ghidra can still decode bytes beyond its start restriction;
the handler verifies the full decoded byte range and rolls back if it crosses
the requested boundary. No partial function or disassembly is committed on
failure, including disassembler error bookmarks and generated references.
There are additional limits of 65,536 visited instructions and 30 seconds for
the flow walk. These bounds are reported in the result and cannot be disabled.
The implementation uses Ghidra's configured language/context; regression fixtures
currently exercise little-endian x86-64.

Success returns one object with `status: prepared`, name, entry address, actual
body `ranges` (inclusive `min_address`/`max_address` and byte length), range count,
total size and contiguity; `disassembled_ranges`, new/reused instruction counts,
`analysis_run: false`, and the requested `scope` with its limits. The window is
an upper bound, not an asserted function body. An unwind candidate is evidence
for choosing a scope; this command does not automatically consume its range.

Read the result independently and verify persistence where appropriate:

```sh
ghidra-cli function get selected_function --project PROJECT --program PROGRAM
ghidra-cli function body selected_function --project PROJECT --program PROGRAM
ghidra-cli decompile selected_function --project PROJECT --program PROGRAM
# Close only your own project bridge when checking saved-project persistence.
ghidra-cli stop --project PROJECT
ghidra-cli function body selected_function --project PROJECT --program PROGRAM
```

Preparation establishes a bounded body from the current decoding and flow
metadata. It does not infer a C prototype, resolve all control-flow uncertainty
or prove correspondence to a source-level function. Ordinary discovery and
query commands do not call this mutation implicitly.
