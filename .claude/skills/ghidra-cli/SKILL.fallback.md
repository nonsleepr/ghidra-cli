---
name: ghidra-cli
description: >
    Use ghidra-cli for reverse engineering tasks: binary analysis,
    decompilation, function inspection, cross-reference analysis,
    pattern discovery, binary patching, and type system management.
    Activate when the user requests binary analysis, decompilation,
    function/symbol/xref inspection, patching, or type annotation.
---

<!-- AUTO-GENERATED from docs/ghidra-cli.1 by build.rs -->
<!-- Do not edit by hand. Run `cargo build` or `scripts/regen-skill.sh`. -->

# ghidra-cli — Fallback Reference

This file is auto-generated for use when `man ghidra-cli` is not available.
For the full reference run `man ghidra-cli` or `ghidra-cli --help`.

## Description

ghidra-cli
drives Ghidra's headless analyzer through a long-lived TCP bridge process,
exposing binary analysis, decompilation, patching, and type annotation as
composable shell commands.

Architecture.
Each invocation connects to (or starts) a per-project bridge:

```
ghidra-cli (Rust/clap)
|  TCP JSON-RPC (localhost, dynamic port)
v
GhidraCliBridge.java  (GhidraScript inside analyzeHeadless JVM)
|
v
Ghidra project  (~/.local/share/ghidra-projects/ by default)
```

There is no separate daemon.  The Java bridge IS the persistent server;
it auto-starts on first use and is keyed by an MD5 of the project path.
Commands are processed sequentially (Ghidra's Program API is not thread-safe).

Output.
When stdout is a TTY the default format is human-readable compact text.
When stdout is a pipe the default is JSONL (one JSON object per line).
Use
--json
or
-o json
to force JSONL regardless of TT

## Commands

### "Setup and health"

setup
Download and install Ghidra automatically.

doctor
Check Ghidra installation, Java, project directory, and config.

init
Interactively initialize configuration.

### "Bridge lifecycle"

start
Start the bridge for a project without running a command.

stop
Stop the running bridge for a project.

restart
Restart the bridge (stop then start).

status
Show bridge status (running/stopped, port, PID).

ping
Verify the bridge responds.

### "Project management"

project create NAME
Create a new Ghidra project.

project list
List all projects in

project delete NAME
Delete a project.

project info [NAME]
Show project metadata.

### "Binary import and analysis"

import BINARY [--project PROJ] [--program NAME] [--detach]
Import a binary into a project and run auto-analysis.

analyze [--project PROJ] [--program NAME] [--detach]
Re-run analysis on an already-imported program.

### "Program management"

program list
List all programs in the project.

program open [--program NAME]
Switch the bridge's active program.

program close
Release the active program from the bridge (without deleting it).

program delete [--program NAME]
Delete a program from the project.

program info
Show metadata for the active program.

program export FORMAT [-o FILE]
Export the program.
FORMAT
is one of
xml ", " json ", " asm ", " c .

### "Inspection"

summary
High-level overview: format, architecture, compiler, section count, symbol count.

stats
Numeric statistics: function count, string count, import/export counts, instruction count.

function list [OPTIONS]
List all functions.  Supports
--filter ", " --fields ", " --limit ", " --sort .

function get TARGET
Show details for one function.
TARGET
is a name, hex address (0x401000), or auto-name (FUN_00401000).

function calls TARGET
List outgoing calls from a function.

function xrefs TARGET
List cross-references to a function.

decompile TARGET [--with-vars] [--with-params]
Decompile a function to C pseudocode.
--with-vars
adds local variable details (name, type, storage).
--with-params
adds parameter details.

disasm TARGET [-n N]
Disassemble a function or
N
instructions starting at an address.

strings list [OPTIONS]
List defined strings.

strings refs STRING
Find cross-references to a string.

symbol list [OPTIONS]
List symbols.

symbol get NAME

symbol create ADDR NAME

symbol delete NAME

symbol rename OLD NEW

memory map
Show memory segments/sections.

memory read ADDR SIZE
Read bytes at address.

memory search PATTERN
Search for byte pattern in memory.

x-ref to TARGET
Cross-references pointing to address/symbol.

x-ref from TARGET
Cross-references originating from address/symbol.

x-ref list TARGET
All cross-references for target.
Note:
the optional TARGET argument is currently ignored at runtime; all xrefs are listed.

graph calls
Full call graph of the program.

graph callers TARGET [--depth N]
Functions that call TARGET (callers, i.e. incoming edges).

graph callees TARGET [--depth N]
Functions called by TARGET (callees, i.e. outgoing edges).

graph export FORMAT
Export the call graph.
FORMAT
is
dot
or
json .

pcode at ADDR
Raw PCode at an address.

pcode function FUNC [--high]
PCode for a whole function.
--high
uses decompiler high-PCode instead of raw listing PCode.

dump imports|exports|functions|strings
Bulk export of a data category.

find string PATTERN
Search for strings matching a substring or pattern.

find bytes HEX
Search for a hex byte pattern, e.g.
4883ec08 .

find function PATTERN
Find functions whose name matches a glob pattern.

find calls TARGET
Find all call sites that call TARGET.

find crypto
Identify crypto constants (S-boxes, magic numbers).

find interesting
List functions with notable properties (large, many xrefs, etc.).

diff functions FUNC1 FUNC2
Compare decompiled output of two functions.

diff programs PROG1 PROG2
Compare two programs in the project.

query TYPE [OPTIONS]
Universal query interface.
TYPE
is any data category (functions, strings, imports, symbols, etc.).

### "Annotation"

comment list
List all user-set comments in the program.
Note: no default limit is applied; all comments are returned.

comment get ADDR
Get comment at address.

comment set ADDR TEXT [--comment-type TYPE]
Set a comment.
TYPE
is one of
EOL ", " PRE ", " POST ", " PLATE ", " REPEATABLE .
Defaults to
EOL .

comment delete ADDR
Delete comment.

function rename OLD NEW
Rename a function (alias:
rename " / " mv ).

function set-signature TARGET --signature STRING
Set function signature from a C-style string, e.g.
"int parse(char *buf, int len)" .

function set-return-type TARGET --type TYPE
Set function return type.

function set-calling-convention TARGET --convention NAME
Set calling convention (e.g.,
__cdecl ", " __stdcall ", " __fastcall ).

function set-var-type TARGET --var NAME --type TYPE
Retype a local variable in a decompiled function.

type list
List all data types in the type manager.

type get NAME
Show definition of a data type.

type create DEFINITION
Create a struct or other type from a C-style definition string.

type create-enum NAME --values K=V,... [--size N]
Create an enum type.
--size
is in bytes (1, 2, 4, or 8; default 4).

type typedef NAME BASE_TYPE
Create a typedef alias.

type add-field STRUCT --name NAME --type TYPE [--offset N]
Add a field to a struct (appends if
--offset
is omitted).

type del-field STRUCT --name NAME
Remove a field from a struct.

type delete NAME
Delete a data type.

type rename OLD NEW
Rename a data type.

type apply ADDR TYPE
Apply a type annotation at an address.

bookmark list [--type TYPE]
List bookmarks, optionally filtered by type (e.g.,
Note ", " Warning ).

bookmark add ADDR [--type TYPE] [--category C] [--comment TEXT]
Add a bookmark.

bookmark delete ADDR [--type TYPE]
Delete bookmark(s) at address.

### "Binary patching"

patch bytes ADDR HEX
Overwrite bytes at address.
HEX
is a hex string, e.g.
9090 .

patch nop ADDR [--count N]
NOP-sled at address.
Note:
--count
is parsed but currently not forwarded to the bridge; only the single instruction at
ADDR
is NOPped.

patch export -o FILE
Export the patched binary to a file.

### "Scripting and automation"

script run PATH [-- ARGS...]
Run a GhidraScript file.

script python CODE
Execute inline Python (Jython) code.

script java CODE
Execute inline Java code.

script list
List available scripts.

batch FILE
Execute a batch file of ghidra-cli commands (one per line).

### "Analyzer control"

analyzer list
List all Ghidra analyzers and their enabled/disabled status.

analyzer set NAME true|false
Enable or disable an analyzer.

analyzer run
Re-run auto-analysis.

### "Configuration"

config list
Show all configuration values.

config get KEY

config set KEY VALUE

config reset
Reset configuration to defaults.

set-default project NAME
Set the default project used when
--project
is o

## Options

--json
Output as JSONL regardless of TTY state.  Shorthand for
"-o json" .

-o " FORMAT" ", " --format " FORMAT"
Output format.

compact
One line per item, human-readable.  Default for TTY.

json
JSONL: one JSON object per line.  Default for pipes.
Pipe through
"jq ."
for pretty printing.

count
Print only the item count.

--fields " FIELD,..."
Comma-separated list of fields to include, e.g.
"name,address,size" .
Reduces output size; any valid field name is accepted.

--limit " N"
Return at most
N
results.  No default limit for
comment list
(see
).

--offset " N"
Skip the first
N
results.

--sort " FIELD,..."
Sort by field(s).  Prefix a field name with
-
for descending order, e.g.
"-size" .

--filter " EXPR"
Server-side filter expression (see
below).

--count
Return only the count of matching results.

--project " NAME"
Project name or path.  May also be set via
GHIDRA_DEFAULT_PROJECT .

--program " NAME"
Program name within the project.  May also be set via
GHIDRA_DEFAULT_PROGRAM .
If omitted and the project contains exactly one program, that program is
auto-selected.

-v ", " --verbose
Increase log verbosity printed to stdout.
Use up to three times:
-v
(warn),
-vv
(info),
-vvv
(debug).

-q ", " --quiet
Suppress non-essential output (progress, bridg

## Examples

### "First analysis of an unknown binary"
```
# Import (auto-analyzes) and check what we have
ghidra-cli import ./target --project rev
ghidra-cli summary --project rev
ghidra-cli stats --project rev

# Find entry points and interesting names
ghidra-cli function list --filter "NOT name ^ 'FUN_'" \e
--fields name,address,size --limit 30 --project rev
ghidra-cli find crypto --project rev
ghidra-cli find string "password" --project rev

# Decompile a suspicious function
ghidra-cli decompile verify_license --project rev
ghidra-cli graph callers verify_license --depth 3 --project rev
ghidra-cli x-ref to verify_license --project rev
```

### "Type annotation to improve decompilation"
```
ghidra-cli type create "struct FileHeader { int magic; short version; int offset; }" \e
--project rev
ghidra-cli type add-field FileHeader --name flags --type "unsigned int" --project rev
ghidra-cli type apply 0x401000 FileHeader --project rev

ghidra-cli function set-signature parse_header \e
--signature "int parse_header(FileHeader *hdr, char *buf, int len)" \e
--project rev
ghidra-cli function set-var-type parse_header \e
--var local_10 --type "FileHeader *" --project rev

# Re-decompile to see improved output
ghidra-cli decompile parse_header --with-vars --with-params --project rev
```

### "Patching a binary"
```
# NOP out a license check
ghidra-cli disasm check_license --project rev
ghidra-cli patch nop 0x401234 --project rev

# Overwrite a jump
ghidra-cli patch bytes 0x401234 "EB0A" --project rev

# Export patched binary
ghidra-cli patch export -o patched_target --project rev
```

### "Scripted batch workflow"
```
# batch.txt
function list --fields name,address --json --project rev
find crypto --project rev
stats --project rev

ghidra-cli batch batch.txt
```

### "Piping through jq"
```
# Get function names sorted by size (largest first)
ghidra-cli function list --json --sort "-size" --fields name,size \e
--project rev | jq '.name'

# Find all functions calling malloc
ghidra-cli find calls malloc --json --project rev | jq '.a

## Environment

GHIDRA_INSTALL_DIR
Path to the Ghidra installation directory (the directory containing
Set automatically by the Nix flake.

GHIDRA_PROJECT_DIR
Base directory for Ghidra projects.
Default:
~/.local/share/ghidra-projects
(Linux/macOS) or equivalent platform data dir.
Note: Ghidra 12 rejects path components starting with
avoid

GHIDRA_DEFAULT_PROJECT
Default value for
--project
when not specified.

GHIDRA_DEFAULT_PROGRAM
Default value for
--program
when not specified.

GHIDRA_CLI_CONFIG
Override path to the configuration file.
Default:

RUST_LOG
Standard Rust logging filter, e.g.
"ghidra_cli=deb

## Diagnostics

"No project specified"
Add
--project NAME
to the command, or run
"ghidra-cli set-default project NAME"
to set a persistent default.

"Ghidra installation directory not configured"
Run
"ghidra-cli setup"
to download and install Ghidra automatically, or set
GHIDRA_INSTALL_DIR
to an existing installation.

"Bridge not responding"
Run
"ghidra-cli stop --project P"
and retry; the bridge auto-starts on the next command.

"Requested project program file(s) not found"
The project directory exists but the named program was not imported.
Run
"ghidra-cli import BINARY --project P --program NAME"
first.

"Multiple programs found"
The project contains more than one program.  Add
"--program NAME"
to select one, or run
"ghidra-cli program list --project P"
to see available names.

"Cannot resolve function target"
The function name or address was not found.  The error message includes
closest matches.  Use
"ghidra-cli find function '*pattern*'"
to search.

"Decompilation failed"
The Ghidra decompiler returned an error.  On macOS ARM64, complex Rust entry
points (especially
main )
may not decompile; try a simpler function such as
factorial .

"Timed out waiting for bridge startup lock"
Another bridge start is in progress (e.g., a concurrent test run).
Wait for it to complete or remove stale
.starting
lock files

## Known Bugs

"x-ref list TARGET"
â the optional TARGET argument is currently ignored at runtime; all xrefs
in the program are listed.

"patch nop --count N"
â the
--count
flag is parsed but not forwarded to the bridge; only the single instruction
at the given address is NOP-ped.

"comment set --comment-type"
â the bridge expects a
comment_type
key but the client sends
type ;
the comment type always falls bac

