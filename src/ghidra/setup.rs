use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

/// GitHub release asset information
#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// GitHub release information
#[derive(Deserialize, Debug)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

/// Normalize a version or release tag to Ghidra's canonical GitHub tag.
pub fn release_tag(version: &str) -> Result<String> {
    let version = version
        .trim()
        .strip_prefix("Ghidra_")
        .unwrap_or(version.trim());
    let version = version.strip_suffix("_build").unwrap_or(version);
    if !regex::Regex::new(r"^\d+\.\d+(?:\.\d+)?$")?.is_match(version) {
        return Err(anyhow!("Invalid Ghidra version: {}", version));
    }
    Ok(format!("Ghidra_{}_build", version))
}

pub fn application_properties(dir: &Path) -> Result<std::collections::HashMap<String, String>> {
    let path = dir.join("Ghidra/application.properties");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Cannot read {}", path.display()))?;
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect())
}

pub fn required_java(dir: &Path) -> Result<u32> {
    application_properties(dir)?
        .get("application.java.min")
        .ok_or_else(|| anyhow!("application.java.min missing"))?
        .parse()
        .context("Invalid application.java.min")
}

fn java_major(text: &str) -> Result<u32> {
    let re = regex::Regex::new(r#"(?:version\s+"|javac\s+)(\d+)(?:\.(\d+))?"#)?;
    let caps = re
        .captures(text)
        .ok_or_else(|| anyhow!("Cannot parse Java version: {}", text.trim()))?;
    let first: u32 = caps[1].parse()?;
    if first == 1 {
        return caps
            .get(2)
            .ok_or_else(|| anyhow!("Invalid legacy Java version"))?
            .as_str()
            .parse()
            .context("Invalid Java version");
    }
    Ok(first)
}

pub fn check_java_tool(tool: &str, minimum: u32) -> Result<u32> {
    let executable = std::env::var_os("JAVA_HOME_OVERRIDE")
        .or_else(|| std::env::var_os("JAVA_HOME"))
        .map(|home| {
            PathBuf::from(home).join("bin").join(format!(
                "{}{}",
                tool,
                std::env::consts::EXE_SUFFIX
            ))
        })
        .unwrap_or_else(|| PathBuf::from(tool));
    let output = std::process::Command::new(&executable)
        .arg("-version")
        .output()
        .with_context(|| format!("Failed to execute {}", executable.display()))?;
    if !output.status.success() {
        return Err(anyhow!(
            "{} -version failed: {}",
            executable.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let major = java_major(&text)?;
    if major < minimum {
        return Err(anyhow!(
            "{} {} detected, but Ghidra requires JDK {} or higher",
            tool,
            major,
            minimum
        ));
    }
    Ok(major)
}

/// Setup defaults to the supported release's JDK minimum.
pub fn check_java_requirement() -> Result<()> {
    check_java_tool("java", 21)?;
    check_java_tool("javac", 21)?;
    Ok(())
}

pub fn decompiler_path(dir: &Path) -> Result<PathBuf> {
    let platform = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux_x86_64",
        ("linux", "aarch64") => "linux_arm_64",
        ("macos", "x86_64") => "mac_x86_64",
        ("macos", "aarch64") => "mac_arm_64",
        ("windows", "x86_64") => "win_x86_64",
        pair => return Err(anyhow!("Unsupported decompiler platform: {:?}", pair)),
    };
    Ok(dir
        .join("Ghidra/Features/Decompiler/os")
        .join(platform)
        .join(format!("decompile{}", std::env::consts::EXE_SUFFIX)))
}

pub fn check_executable(path: &Path) -> Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("Not found: {}", path.display()))?;
    if !metadata.is_file() {
        return Err(anyhow!("Not a file: {}", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(anyhow!("Not executable: {}", path.display()));
        }
    }
    Ok(())
}

/// Resolve the download URL for a Ghidra release.
/// If version is None, fetches the latest release.
pub async fn resolve_version_url(version: Option<String>) -> Result<(String, String, String)> {
    let mut headers = reqwest::header::HeaderMap::new();
    // Use GITHUB_TOKEN if available (avoids 60 req/hour unauthenticated rate limit)
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse()?,
        );
    }

    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .default_headers(headers)
        .build()?;

    let release: GithubRelease = if let Some(ver) = version {
        // Fetch specific version
        let tag = release_tag(&ver)?;
        let url = format!(
            "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/{}",
            tag
        );
        println!("Fetching release info for Ghidra {}...", ver);
        client
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .context(format!("Could not find Ghidra version {}", ver))?
            .json()
            .await?
    } else {
        // Fetch latest release
        let url = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest";
        println!("Fetching latest Ghidra release info...");
        client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?
    };

    println!("Found release: {}", release.tag_name);

    // Find the zip file in assets
    let zip_asset = release
        .assets
        .iter()
        .find(|a| a.name.ends_with(".zip") && !a.name.contains("src"))
        .ok_or_else(|| anyhow!("No zip distribution found in release assets"))?;

    Ok((
        zip_asset.browser_download_url.clone(),
        zip_asset.name.clone(),
        release.tag_name,
    ))
}

/// Download a file with progress bar.
pub async fn download_file(url: &str, path: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("ghidra-cli")
        .build()?;

    let res = client
        .get(url)
        .send()
        .await?
        .error_for_status()
        .context("Download request failed")?;

    let total_size = res.content_length().unwrap_or(0);

    let pb = ProgressBar::new(total_size);
    pb.set_style(ProgressStyle::default_bar()
        .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));
    pb.set_message(format!(
        "Downloading {}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    let mut file = File::create(path)?;
    let mut stream = res.bytes_stream();

    while let Some(item) = stream.next().await {
        let chunk = item.context("Error reading download stream")?;
        file.write_all(&chunk)?;
        pb.inc(chunk.len() as u64);
    }

    pb.finish_with_message("Download complete");
    Ok(())
}

/// Extract a zip file to the target directory.
/// Returns the path to the extracted Ghidra directory.
pub fn extract_zip(zip_path: &Path, target_dir: &Path) -> Result<PathBuf> {
    println!("Extracting...");

    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let total_files = archive.len();
    let pb = ProgressBar::new(total_files as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len}",
            )?
            .progress_chars("#>-"),
    );
    pb.set_message("Extracting files");

    // Track the root directory from the archive
    let mut root_dir: Option<PathBuf> = None;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        // Capture the root directory (first path component)
        if root_dir.is_none() {
            if let Some(first_component) = file.enclosed_name().and_then(|p| p.components().next())
            {
                root_dir = Some(target_dir.join(first_component.as_os_str()));
            }
        }

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode)).ok();
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message("Extraction complete");

    root_dir.ok_or_else(|| anyhow!("Could not determine extracted directory"))
}

/// Install Ghidra to the specified directory.
/// Returns the path to the installed Ghidra directory.
pub async fn install_ghidra(version: Option<String>, target_dir: PathBuf) -> Result<PathBuf> {
    // Resolve version and get download URL
    let (download_url, filename, tag) = resolve_version_url(version).await?;

    println!("Installing Ghidra {} to: {}", tag, target_dir.display());

    // Download the zip file
    let zip_path = target_dir.join(&filename);
    download_file(&download_url, &zip_path).await?;

    // Extract the zip
    let install_path = extract_zip(&zip_path, &target_dir)?;

    // On macOS, remove the quarantine extended attribute so Gatekeeper does not
    // block the native decompiler binary (and other executables) from running.
    // Without this, the first run after download would fail with "Could not find
    // decompiler executable" even though the binary exists.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("xattr")
            .args(["-dr", "com.apple.quarantine"])
            .arg(&install_path)
            .status();
    }

    // Cleanup zip file
    if let Err(e) = std::fs::remove_file(&zip_path) {
        println!("⚠ Could not remove zip file: {}", e);
    }

    Ok(install_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tags() {
        for input in ["12.1.4", "12.1.4_build", "Ghidra_12.1.4_build"] {
            assert_eq!(release_tag(input).unwrap(), "Ghidra_12.1.4_build");
        }
        assert_eq!(release_tag("12.1").unwrap(), "Ghidra_12.1_build");
        for input in ["", "latest", "../12.1", "12.1/build"] {
            assert!(release_tag(input).is_err());
        }
    }

    #[test]
    fn java_versions() {
        assert_eq!(java_major("openjdk version \"21.0.12\"").unwrap(), 21);
        assert_eq!(java_major("javac 21.0.12").unwrap(), 21);
        assert_eq!(java_major("java version \"1.8.0\"").unwrap(), 8);
        assert!(java_major("unrecognized").is_err());
    }

    #[test]
    fn test_check_java_fails_gracefully() {
        // This just ensures the function doesn't panic
        // It may succeed or fail depending on the system
        let _ = check_java_requirement();
    }
}
