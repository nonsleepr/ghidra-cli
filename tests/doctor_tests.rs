//! Diagnostics are executable checks, with deterministic missing-tool cases.
#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    fn executable(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[test]
    fn required_checks_fail_individually() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        std::fs::create_dir_all(dir.join("Ghidra")).unwrap();
        std::fs::write(
            dir.join("Ghidra/application.properties"),
            "application.version=12.1.4\napplication.java.min=21\n",
        )
        .unwrap();
        let headless = dir.join("support/analyzeHeadless");
        let decompiler = ghidra_cli::ghidra::setup::decompiler_path(dir).unwrap();
        let java = dir.join("bin/java");
        let javac = dir.join("bin/javac");
        executable(&headless, "#!/bin/sh\nexit 0\n");
        executable(&decompiler, "#!/bin/sh\nexit 0\n");
        executable(&java, "#!/bin/sh\necho 'openjdk version \"21.0.1\"' >&2\n");
        executable(&javac, "#!/bin/sh\necho 'javac 21.0.1'\n");
        let run = || {
            assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
                .env("GHIDRA_INSTALL_DIR", dir)
                .env("JAVA_HOME", dir)
                .env_remove("JAVA_HOME_OVERRIDE")
                .env("GHIDRA_CLI_CONFIG", dir.join("config.yaml"))
                .arg("doctor")
                .output()
                .unwrap()
        };
        assert!(run().status.success());
        for path in [&headless, &decompiler, &javac] {
            let contents = std::fs::read(path).unwrap();
            std::fs::remove_file(path).unwrap();
            let output = run();
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stdout).contains("FAILED"));
            executable(path, std::str::from_utf8(&contents).unwrap());
        }
        executable(&java, "#!/bin/sh\necho 'openjdk version \"17.0.1\"' >&2\n");
        let output = run();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("requires JDK 21"));
    }
}
