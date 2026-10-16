# Static discovery without full analysis

These queries inspect loaded memory and existing metadata. They do not run an
analyzer or create strings, instructions, references, types, or functions.
The CLI refreshes an older running bridge when these new query operations are
first requested. Addresses are in Ghidra's address space, including the program's image-base
adjustment. Supply `--project PROJECT --program PROGRAM` as usual.

## Strings

```sh
ghidra-cli find string 'authentication failed' --details
ghidra-cli find string 'ExactCase' --case-sensitive --limit 50
ghidra-cli strings refs 'authentication failed' --discover \
  --start 0x401000 --end 0x410000 --scan-bytes 1048576
```

`find string` merges defined strings and printable UTF-8 byte runs even when
some matches are already defined. Matching is case-insensitive by default in
both sources; substring matches report the beginning of the complete discovered
run. Duplicate values at different addresses remain separate results. Defined
UTF-16 strings are searchable; undefined UTF-16 strings are not discovered.

Raw search examines up to 64 MiB of initialized memory in block order, including
loader-created blocks. Each run is inspected up to 4096 bytes. Search limits
therefore apply even when no matches are found. The default result limit is 1000;
`--limit` accepts 1 through 100000. `--details` returns an envelope containing
`results`, `count`, and `search`, including byte coverage, limits and truncation.
Without `--details`, output keeps the existing JSONL row layout; an incomplete
search emits a diagnostic on stderr. Byte results distinguish termination and
preview truncation. For defined strings, termination is reported as unknown.

`strings refs` uses recorded references by default, including references to the
interior of a defined string. `--discover` also finds undefined strings and
scans executable memory using Ghidra's decoder. Initial support is **little-endian
x86-64 direct operands**, including RIP-relative addressing and direct constant
p-code address candidates. An immediate resembling an address is only a
candidate; intended pointer use is not proven. Register dataflow and pointer
chains are unsupported. A linear scan can miss instructions after an incorrect
code boundary or decode embedded data as instructions.

The executable scan defaults to 1 MiB (maximum 64 MiB), with inclusive
`--start`/`--end` bounds. The result's `discovery` object reports the actual
ranges, byte count, decoding failures, truncation and limitations, including the
separate string-memory scan. Recorded references are gathered program-wide;
these executable bounds apply to the decoded scan. `--limit` caps returned
reference rows (default 1000); discovering string locations itself is capped at
10000 matches. Recorded and decoded evidence is deduplicated by source/target
address, preferring recorded evidence. Each row reports `reference_source`,
`target_address`, `interior_offset`, and `from_function`; a missing function is
explicitly unknown, not assigned to the nearest preceding start. The existing
`results`/`count`/`pattern` envelope is retained.

## Disassembly previews

```sh
ghidra-cli disasm 0x401000 -n 20 --resolve-strings
ghidra-cli disasm 0x401000 --bytes 128 --resolve-strings --discover
```

`--resolve-strings` adds a `string_preview` to references whose targets have
string data or printable UTF-8 candidates. Previews are bounded to 256 bytes
for raw memory or 256 UTF-16 code units for defined strings and report their
source, encoding, termination and truncation. Raw candidates require at least
four characters. Human output escapes control characters in annotations.

`--discover` requires `--resolve-strings` and enables direct x86-64 operand
candidates plus temporary decoding of undefined instructions. It has the same
reference-form limitations as string discovery. Existing operands and recorded
references are preserved. Default disassembly output is unchanged.

## Unwind candidates

```sh
ghidra-cli function candidates --source unwind --limit 100
ghidra-cli function candidates --address 0x401003
```

Initial support reads the ELF `.eh_frame_hdr` index, then parses CIE/FDE records
to obtain covered ranges. It handles program endianness and pointer size;
fixed unsigned/signed 16/32/64-bit, native-pointer and ULEB128/SLEB128 values;
absolute, PC-relative, header-data-relative, aligned and indirect address
encodings where the base is available. Text-relative and function-relative
encodings, missing data-relative bases, and unrecognized CIE augmentations are
explicitly unsupported. CIE versions 1, 3 and 4 and the `zLPRS` augmentation
fields are supported. Record, augmentation and table bounds are checked. The
index has a hard safety bound of one million entries.

Rows keep `start`, `fde_address`, `next_indexed_start`, and the actual
`range_start`/`range_end_exclusive` separate. A failed FDE decode yields a
`range_error`, not an invented range end. Address lookup uses decoded FDE ranges;
if range decoding fails, an exact indexed-start match can still return that
candidate with its error. Existing Ghidra functions are attached when present.
The result reports an absent header separately from an empty match, and malformed
headers fail explicitly. Results default to a 1000-row limit, with truncation
reported. This is an unwind candidate index, not a complete function inventory;
it does not group split ranges into functions.

## Vtable inspection

```sh
ghidra-cli vtable inspect 0x405050 --slots 12
```

Initial support is **64-bit ELF using the Itanium header layout**. The supplied
address must be the address point (the first method slot), rather than the
header preceding it. A slot count is required, between 1 and 512. Inspection
reports the signed offset-to-top, typeinfo pointer/name when readable, and
exactly the requested slots, including null, unmapped, non-executable and
unreadable entries. Recorded symbols, functions and thunk flags are attached
when available. Missing function metadata does not terminate inspection.

The caller supplies the table location and bound; inspection does not prove
table membership or infer its boundaries. Automatic RTTI discovery,
demangling/inheritance reconstruction, decoded thunk adjustments, relative
vtables, function-descriptor ABIs and MSVC layouts are outside this release.
