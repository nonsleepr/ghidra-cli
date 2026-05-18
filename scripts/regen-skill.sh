#!/usr/bin/env bash
# scripts/regen-skill.sh
#
# Regenerate .claude/skills/ghidra-cli/SKILL.fallback.md from docs/ghidra-cli.1.
# Run this manually or wire it into a pre-commit hook.
#
# Usage:
#   scripts/regen-skill.sh
#
# The actual generation is done by build.rs, so a plain `cargo build`
# (inside the Nix dev shell if Cargo is not on PATH otherwise) is sufficient.
# This script just ensures the build triggers even when the Rust source
# has not changed, by touching docs/ghidra-cli.1 first.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

touch docs/ghidra-cli.1

if command -v cargo &>/dev/null; then
    cargo build -q
else
    nix develop --command cargo build -q
fi

echo "Regenerated .claude/skills/ghidra-cli/SKILL.fallback.md"
