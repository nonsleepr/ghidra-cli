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

Docker is the primary way this tool is run — check for a usable container before assuming a
native `ghidra-cli` binary. Order of checks:

1. Is a `ghidra-cli`-image container already running (`docker ps`)? Use it directly with `docker
   exec` (see below).
2. Is `ghidra-cli` on `PATH` (native/Nix/`cargo install`)? Run it directly, no `docker` prefix.
3. Otherwise, build the image from this repo's `Dockerfile` (`docker build -t ghidra-cli .`) and
   start a container as below.

## Running via Docker (primary)

Run commands through a single long-lived container rather than `docker run --rm` per command —
each `import`/`analyze`/query auto-starts a per-project Ghidra bridge that takes ~10-30s to boot,
and that bridge dies with the container. A fresh container per command pays that cost every time;
a long-lived one keeps the bridge warm.

Start the container once (adjust the image name/tag and host paths as needed):

```bash
docker run -d --name ghidra-cli \
  -v "$PWD/projects:/projects" -v "$PWD/binaries:/binaries:ro" \
  --entrypoint sleep ghidra-cli:latest infinity
```

Then run every ghidra-cli command through `docker exec` against that container. Use an absolute
project path inside the container, without the `.gpr` suffix. A normal `import` starts Ghidra's
analysis, so a second `analyze` is not an import prerequisite:

```bash
docker exec ghidra-cli ghidra-cli import /binaries/app --project /projects/myproject --program app
docker exec ghidra-cli ghidra-cli decompile main --project /projects/myproject --program app
docker exec ghidra-cli ghidra-cli function list --project /projects/myproject --program app
```

Binaries must live under the mounted `/binaries` path (not the host path) since commands run
inside the container. `--project`/`--program` are still required per command exactly as in the
native case — the container doesn't remember them between `docker exec` calls. Decompilation
returns JSON with a `code` field containing the pseudocode.

### Large binaries: configure analyzers before analysis

If default import analysis is too slow or an analyzer fails, import with Ghidra's bundled
`analyzeHeadless -noanalysis`, then use `ghidra-cli` to configure and run analysis. This was
verified with Ghidra 12.1.2 and `ghidra-cli` 0.1.10 on a stripped C++ ELF. Adjust the bundled
Ghidra path for the installed version:

```bash
docker exec ghidra-cli /opt/ghidra/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  /projects myproject -import /binaries/app -noanalysis
docker exec ghidra-cli ghidra-cli program list --project /projects/myproject
docker exec ghidra-cli ghidra-cli analyzer list --project /projects/myproject --program app
```

Disable only analyzers shown to cause a problem for that binary. For the LiveU Hub binary,
`ELF Scalar Operand References` spent several minutes in relocation processing and
`GCC Exception Handlers` produced malformed call-site errors. In this CLI version, omitting the
optional `[ENABLED]` argument disables the named analyzer; confirm its response says
`enabled:false`. This reduces the references or metadata those analyzers could otherwise add.

```bash
docker exec ghidra-cli ghidra-cli analyzer set --project /projects/myproject --program app \
  'ELF Scalar Operand References'
docker exec ghidra-cli ghidra-cli analyzer set --project /projects/myproject --program app \
  'GCC Exception Handlers'
docker exec ghidra-cli ghidra-cli analyze --project /projects/myproject --program app --detach
```

Wait for analysis to finish before dependent queries; the bridge processes requests serially.
The `--detach` option avoids keeping a long CLI request open. In the verified Hub run, a
non-detached CLI request timed out while Ghidra continued analyzing and completed successfully.
Use `program list` and `summary` to inspect the saved result, then decompile by function name or
address. `ghidra-cli stop --project /projects/myproject` closes the bridge; a later query can
reopen the saved project.

When finished, stop and remove only a container you created:

```bash
docker stop ghidra-cli && docker rm ghidra-cli
```

This is the same long-running pattern as `docker-compose.yml` in this repo (`docker compose up
-d` + `docker compose exec ghidra-cli ghidra-cli ...`) — use whichever of plain `docker` or
`docker compose` is available. See the README's Docker section for build instructions and the
`--build-arg GHIDRA_VERSION` / `--secret id=github_token` options.

## Running natively (fallback)

If `ghidra-cli` is already on `PATH` (installed via Nix or `cargo install`, no container in
play), skip Docker entirely and run commands directly — same commands and flags as above, minus
the `docker exec ghidra-cli` prefix.

## Full command reference

Try `man ghidra-cli` first — it has the complete reference (every command, flag, filter
expression syntax, environment variables, diagnostics for common errors). Inside a Docker
container, prefix with `docker exec ghidra-cli`, e.g. `docker exec ghidra-cli man ghidra-cli`.

`man` is usually **not available inside the Docker image** (no man-db installed, no shell
needed since `ENTRYPOINT` is the binary itself) and may also be missing for a plain `cargo
install` outside Nix. When `man ghidra-cli` fails, fall back to `--help`, which ships inside the
binary and always works:

```bash
ghidra-cli --help                    # top-level command list
ghidra-cli function --help           # subcommand group list (e.g. all `function` verbs)
ghidra-cli function set-no-return --help   # flags for one specific command
```

`--help` output doesn't include the man page's prose sections (filter expression language,
function-target resolution order, environment variables, example workflows) — for those, read
this file's sections above, or `docs/ghidra-cli.1` directly if the repo is checked out
(`man ./docs/ghidra-cli.1` works without installing it, or pipe it through a man renderer:
`man -l docs/ghidra-cli.1` / `groff -man -Tutf8 docs/ghidra-cli.1 | less`).

## Verification workflow for decompiled output

Ghidra's decompiler infers high-level structure (loops, conditionals, argument counts, exception
unwinding) from pattern-matching over the disassembly, and it silently drops or folds things it
can't model well — vararg calls, tail calls, setjmp/longjmp, hand-written or compiler-folded
exception paths, and indirect calls with incomplete type info are the common failure modes. On a
large stripped C++ ELF, pseudocode omitting call arguments or presenting an exception path as
ordinary control flow was not a decompiler bug report — it was the decompiler's best-effort
guess, and the ground truth was in the disassembly underneath.

Treat `decompile` output as a hypothesis, not a fact, and verify the parts you're going to rely on:

1. **Decompile first** (`function decompile TARGET` / `decompile TARGET`) to get the overall shape
   and identify anything that looks off — a call with fewer arguments than the callee's known
   signature, a branch condition that doesn't match surrounding logic, a `noreturn`-shaped call
   (e.g. an assert/abort helper) whose code continues past it as if it returns.
2. **Disassemble the questionable range** (`disasm TARGET -n N`, or `function disasm TARGET`) and
   read the actual instructions at and around the call/branch in question. Check the real operand
   count and calling convention against what the decompiler rendered.
3. **Follow references** with `x-ref to`/`x-ref from` (or `graph callers`/`graph callees`) to
   confirm a call target's real signature, and `function get TARGET` to check whether a helper is
   marked `no_return` — if a function such as an assert/panic helper is incorrectly inferred as
   returning, every call site after it gets misleading "continues normally" pseudocode. See
   `function set-no-return` below to correct it once confirmed, which usually fixes the
   downstream decompilation for all of its callers.
4. **Check function boundaries** when something looks spliced in or missing — Ghidra sometimes
   merges inlined exception-handling blocks into a function's body, or a function's body is
   disjoint across non-contiguous ranges. Inspect with disassembly at the suspect addresses rather
   than trusting that the decompiled function covers exactly what the source function did.
5. **Report findings with a verified/inferred distinction.** When summarizing analysis to the
   user, say what was confirmed via disassembly/xrefs/symbol data vs. what is only the
   decompiler's rendering — don't present inferred pseudocode as equivalent to checked disassembly.

Decompiler success responses do not currently include a `warnings` field distinguishing partial
or suspect analysis from a clean decompile, so the only reliable signal for "this needs a second
look" is suspicious-looking output plus the verification steps above, not an explicit flag in the
response. If a `decompile` call fails outright, the response includes a human-readable reason
(decompiler timeout, cancellation, process failure, or the Ghidra decompiler's own error message).

## Address conventions

`ghidra-cli` accepts and returns addresses in a few different forms; these are not
interchangeable and conflating them is a common source of confusion:

- **Ghidra address-space-qualified form**, e.g. `ram:00401000` — this is what Ghidra stores
  internally and returns from commands like `function get`/`function list` (`address`,
  `entry_point` fields) and `program info` (`image_base`). The `ram:` prefix is the default
  address space name for most binaries; other spaces (e.g. `register:`, overlay segments) can
  appear for special memory regions.
- **Bare hex literal**, e.g. `0x401000` — accepted as CLI input (`TARGET`/`--target`/`address`
  arguments) and resolved against the current program's default address space. This is usually
  the *Ghidra-space address* (space + image base already applied), not a raw ELF file offset.
- **Auto-generated name form**, e.g. `FUN_00401000` or `DAT_00401000` — Ghidra's default naming
  for unnamed functions/data at a given address; also accepted directly as a target.
- **Symbol or function name**, e.g. `main`, `check_license` — resolved via the symbol table.

For a statically-linked or non-PIE ELF, the Ghidra `ram:` address typically equals the ELF's
virtual address (`p_vaddr` from the program headers / `sh_addr` from section headers), because
Ghidra's default image base for such binaries is usually `0`. For a PIE/shared-object ELF, Ghidra
applies its own image base (visible via `program info`'s `image_base` field, or the equivalent
`summary` output) on top of the ELF's load-relative virtual addresses — a raw ELF file offset
(as reported by `readelf`/`objdump -h` for section file offsets, distinct from virtual addresses)
requires subtracting the section's file-offset-to-vaddr delta before it matches a Ghidra address,
and virtual addresses require adding Ghidra's image base if it differs from the ELF's preferred
load address. When cross-checking against `objdump -d`/`readelf`, compare against the ELF's own
virtual addresses, and account for `image_base` if `program info` shows one that isn't `0`.
