# Build and bridge diagnostics

Use explicit JSON output to capture each side of a report:

```sh
ghidra-cli version --json
ghidra-cli status --json --project /absolute/path/project
ghidra-cli doctor
```

`version` identifies the client executable, package version, target, build ID,
embedded bridge script hash and expected protocol version. The content-based
build ID hashes the Rust/Java source tree, Cargo manifest/lockfile, build script,
compiler version, target, profile and Rust flags. These MD5 identifiers diagnose
differences; they are not authenticity guarantees. Builds may differ between
platforms/profiles. They do not fingerprint the installed Ghidra/JDK runtime.
`--version` retains the short package-version output.

Source revision is `unknown` unless supplied at build time using
`GHIDRA_CLI_SOURCE_REVISION`. CI supplies its checked-out revision; clean Nix
flake builds supply their revision. Dirty/archive builds retain their content
ID without claiming an unavailable revision. Docker accepts the same name as
an optional `--build-arg`.

`status` observes the selected project without starting or refreshing a bridge.
It reports the client identity, configured project path, canonical project path,
actual project key, PID/port files, live PID/port, and the bridge's loaded program,
uptime, script hash, originating CLI build ID, protocol and Ghidra/JDK runtime.
Older bridges lacking identity fields are reported as `unknown`, not inferred
from the package version. A failed extended-info query is included as a diagnostic
error. Status may clean stale lifecycle files through the existing liveness check;
it does not alter program metadata.

Compare both path and lifecycle-file locations when investigating repeated
startup: relative/absolute aliases, symlinks and different XDG/runtime settings
can select different keys or state directories. The actual project key still
uses the existing path spelling; this change does not migrate bridge ownership.
Keep one consistent absolute project path across commands.

A script mismatch alone does not restart a live bridge. A declared protocol
mismatch rejects query reuse and asks for an explicit project restart. Legacy
bridges without a declared protocol retain the existing behavior: an unsupported
command triggers one bridge refresh and retry. That refresh prints its reason and
both identities to stderr unless quiet; the file log also records it. Startup
without a live bridge and explicit restarts have corresponding file-log reasons.
Do not restart an unrelated investigation's bridge just to collect diagnostics.

For selective preparation of an unanalyzed import, use the explicit mutating
[`function prepare`](function-preparation.md) command with a reviewed entry and
an explicit bound. It provides atomic disassembly/function creation and reports
the actual body. Inline Java remains available for cases outside its coverage,
but the generic `disassemble`/`createFunction` route can follow control flow and
is not bounded by this interface.

For signature reports, capture `version`, `status` and immediate `function get`
output; a successful edit response alone does not demonstrate persistence after
reopen. A synthetic stripped ELF reproduces the missing-instruction creation
failure, and now verifies bounded preparation, two-pointer signature readback,
decompilation and stop/reopen with unknown calling convention/custom storage.
The historical investigation's signature discrepancy remains unreproduced.
