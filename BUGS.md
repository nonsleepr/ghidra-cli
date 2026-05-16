# Known Bugs

## B-1: `function calls` / `graph callers` / `graph callees` return empty results

**Commands:** `ghidra function calls FUNC`, `ghidra graph callers FUNC`, `ghidra graph callees FUNC`

**Root cause (bridge):**
- `handleFindCalls` did `getReferencesTo(entryPoint)` — returns callers, not callees. Also, `function calls` is supposed to return *outgoing* calls FROM the function body, not inbound.
- `findCalleesRecursive` calls `refMgr.getReferencesFrom(func.getEntryPoint())` — only queries refs from the single entry point address, not the entire function body. Call instructions are scattered through the body.
- `findCallersRecursive` correctly uses `getReferencesTo(entryPoint)` for callers; this works, but `graph callers main` returns `[]` because `main` is only called via `_start` with a PARAM ref type, not a CALL ref type.

**Fix:**
- `handleFindCalls`: iterate all instructions in the function body, collect CALL references from each.
- `findCalleesRecursive`: same — iterate all addresses in the function's address set, get refs from each.
- `findCallersRecursive`: broaden ref type check to include UNCONDITIONAL_CALL, CONDITIONAL_CALL, COMPUTED_CALL, PARAM, and INDIRECTION in addition to `isCall()`.

**Status:** Fixed — iterate function body addresses for callee/outgoing calls; broaden ref type check for callers.

---

## B-2: `strings refs STRING` errors with "Cannot resolve function target"

**Command:** `ghidra strings refs "some string"`

**Root cause (Rust):**
- `StringsCommands::Refs` dispatches to `client.xrefs_to(args.string)`, which sends `xrefs_to` with the string text as an address. The bridge tries to parse the text as an address and fails.
- There is no `string_refs` bridge handler.

**Fix:**
- Add `string_refs` bridge handler: find defined strings matching the pattern, collect their addresses, return xrefs to each.
- Add `client.string_refs(pattern)` in Rust.
- Update `main.rs` to dispatch `StringsCommands::Refs` → `client.string_refs`.

**Status:** Fixed.

---

## B-3: `patch nop` / `patch bytes` fails with "Memory change conflicts"

**Command:** `ghidra patch nop ADDR [--count N]`, `ghidra patch bytes ADDR HEX`

**Root cause (bridge):**
- `memory.setBytes()` fails on Ghidra memory blocks marked read-only (e.g., `.text` which is `rx` but not `w`). Ghidra enforces block permissions in `Memory.setBytes()`.

**Fix:**
- Before patching, find the `MemoryBlock` containing the address, save its `isWrite()` flag, call `block.setWrite(true)`, then patch, then restore the original flag.

**Status:** Fixed.

---

## B-4: `dump imports` / `dump exports` ignore `--limit`

**Commands:** `ghidra dump imports --limit N`, `ghidra dump exports --limit N`

**Root cause:**
- Bridge handlers `handleListImports()` / `handleListExports()` accept no arguments and apply no limit.
- Rust client sends `send_command("list_imports", None)` with no args.

**Fix:**
- Change bridge handlers to accept `JsonObject args` and respect a `limit` parameter.
- Update client to pass `limit` in the args JSON.

**Status:** Fixed.
