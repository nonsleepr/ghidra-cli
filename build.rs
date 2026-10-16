use std::{fs, path::Path, process::Command};

fn sources(path: &Path, context: &mut md5::Context) {
    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            sources(&entry, context);
        } else {
            context.consume(entry.to_string_lossy().replace('\\', "/").as_bytes());
            context.consume([0]);
            context.consume(fs::read(entry).unwrap());
            context.consume([0]);
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=src");
    let mut context = md5::Context::new();
    sources(Path::new("src"), &mut context);
    for file in ["Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={file}");
        context.consume(fs::read(file).unwrap());
    }
    for key in [
        "TARGET",
        "PROFILE",
        "OPT_LEVEL",
        "DEBUG",
        "CARGO_ENCODED_RUSTFLAGS",
    ] {
        context.consume(std::env::var(key).unwrap_or_default());
    }
    let compiler = Command::new(std::env::var_os("RUSTC").unwrap())
        .arg("--version")
        .output()
        .unwrap();
    context.consume(compiler.stdout);
    println!(
        "cargo:rustc-env=GHIDRA_CLI_BUILD_ID={:x}",
        context.compute()
    );
    println!(
        "cargo:rustc-env=GHIDRA_CLI_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!("cargo:rerun-if-env-changed=GHIDRA_CLI_SOURCE_REVISION");
    // Archives and sandboxed builds may have no Git metadata. The content-based
    // build ID above remains available and does not pretend to be a revision.
    let revision = std::env::var("GHIDRA_CLI_SOURCE_REVISION").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=GHIDRA_CLI_REVISION={revision}");
}
