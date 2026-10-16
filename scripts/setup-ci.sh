#!/usr/bin/env bash
# Install the pinned runtime, including the decompiler omitted from macOS ZIPs.
set -euo pipefail
version=$(cat ghidra-version)
if report=$(cargo run -- doctor 2>&1); then
    printf '%s\n' "$report"
    if [[ "$report" == *"Ghidra version: OK ($version)"* ]]; then
        exit 0
    fi
else
    printf '%s\n' "$report"
fi
cargo run -- setup --version "$version"
if [[ $(uname -s) == Darwin ]]; then
    ghidra_dir="$HOME/Library/Application Support/ghidra-cli/ghidra/ghidra_${version}_PUBLIC"
    case $(uname -m) in
        arm64) platform=mac_arm_64; arch=arm64 ;;
        x86_64) platform=mac_x86_64; arch=x86_64 ;;
        *) echo 'Unsupported macOS architecture' >&2; exit 1 ;;
    esac
    decompiler="$ghidra_dir/Ghidra/Features/Decompiler/os/$platform/decompile"
    if [[ ! -x "$decompiler" ]]; then
        mkdir -p "$HOME/code/thirdparty"
        build_dir=$(mktemp -d "$HOME/code/thirdparty/ghidra-native-ci.XXXXXX")
        trap 'rm -rf "$build_dir"' EXIT
        git clone --depth=1 --filter=blob:none --sparse \
            --branch "Ghidra_${version}_build" \
            https://github.com/NationalSecurityAgency/ghidra.git "$build_dir"
        git -C "$build_dir" sparse-checkout set Ghidra/Features/Decompiler/src/decompile/cpp
        cpp_dir="$build_dir/Ghidra/Features/Decompiler/src/decompile/cpp"
        make -C "$cpp_dir" ghidra_opt ARCH_TYPE="-arch $arch" \
            ADDITIONAL_FLAGS="" OSDIR="$platform" CXX="clang++ -std=c++11"
        mkdir -p "$(dirname "$decompiler")"
        install -m755 "$cpp_dir/ghidra_opt" "$decompiler"
    fi
fi
report=$(cargo run -- doctor)
printf '%s\n' "$report"
[[ "$report" == *"Ghidra version: OK ($version)"* ]]
