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
  -v "$PWD/projects:/projects" -v "$PWD/binaries:/binaries" \
  --entrypoint sleep ghidra-cli:latest infinity
```

Then run every ghidra-cli command through `docker exec` against that container:

```bash
docker exec ghidra-cli ghidra-cli import /binaries/app --project myproject --program app
docker exec ghidra-cli ghidra-cli analyze --project myproject --program app
docker exec ghidra-cli ghidra-cli decompile main --project myproject --program app
docker exec ghidra-cli ghidra-cli function list --project myproject --program app
```

Binaries must live under the mounted `/binaries` path (not the host path) since commands run
inside the container. `--project`/`--program` are still required per command exactly as in the
native case — the container doesn't remember them between `docker exec` calls.

When finished:

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

For full documentation, run:

```
man ghidra-cli
```

or use the `--help` / `<subcommand> --help` flags. Inside a Docker container, prefix with `docker
exec ghidra-cli`, e.g. `docker exec ghidra-cli ghidra-cli --help`.

If `man ghidra-cli` is not available (package not installed globally), see `SKILL.fallback.md`
in this directory — it is auto-generated from `docs/ghidra-cli.1` by `build.rs` on every build.
