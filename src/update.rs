//! Self-update from this repository's stable GitHub release assets.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

const API: &str = "https://api.github.com/repos/bl4ckr0ss3/knife/releases/latest";
const DOWNLOAD: &str = "https://github.com/bl4ckr0ss3/knife/releases/download/";
const MAX_BINARY: u64 = 256 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct UpdateResult {
    pub current_version: String,
    pub latest_version: String,
    pub target: String,
    pub updated: bool,
    pub update_available: bool,
    pub backup: Option<String>,
    pub message: String,
}

#[derive(Debug)]
struct Release {
    version: semver::Version,
    name: String,
    url: String,
    digest: String,
}

fn target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") if cfg!(target_env = "gnu") => Ok("x86_64-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") if cfg!(target_env = "msvc") => Ok("x86_64-pc-windows-msvc"),
        _ => bail!(
            "no prebuilt update for this platform; use cargo install reknife --locked --force"
        ),
    }
}

fn release(value: &Value, target: &str) -> Result<Release> {
    if value["draft"].as_bool() != Some(false) || value["prerelease"].as_bool() != Some(false) {
        bail!("latest release is not stable");
    }
    let tag = value["tag_name"].as_str().context("release tag missing")?;
    let version = semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag))?;
    if !version.pre.is_empty() {
        bail!("prerelease updates are unsupported");
    }
    let name = format!(
        "knife-{target}.{}",
        if target.contains("windows") {
            "zip"
        } else {
            "tgz"
        }
    );
    let assets = value["assets"]
        .as_array()
        .context("release assets missing")?;
    let matches = assets
        .iter()
        .filter(|asset| asset["name"].as_str() == Some(&name))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("release must contain exactly one {name} asset");
    }
    let asset = matches[0];
    let expected_url = format!("{DOWNLOAD}{tag}/{name}");
    if asset["browser_download_url"].as_str() != Some(&expected_url) {
        bail!("unexpected release asset URL");
    }
    let digest = asset["digest"]
        .as_str()
        .and_then(|s| s.strip_prefix("sha256:"))
        .context("release asset has no SHA-256 digest; refusing unverified update")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid release asset digest");
    }
    Ok(Release {
        version,
        name,
        url: expected_url,
        digest: digest.to_ascii_lowercase(),
    })
}

fn fetch(url: &str, limit: usize, seconds: u64) -> Result<Vec<u8>> {
    let curl = crate::providers::process::find_on_path("curl")
        .context("knife update requires curl on PATH")?;
    let args = [
        "--disable",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--connect-timeout",
        "10",
        "--max-time",
        &seconds.to_string(),
        "--user-agent",
        "knife-update",
        "--header",
        "Accept: application/vnd.github+json",
        url,
    ]
    .into_iter()
    .map(OsString::from)
    .collect::<Vec<_>>();
    let output = crate::providers::process::run_process(
        &curl,
        args,
        Duration::from_secs(seconds + 5),
        limit,
    )?;
    if !output.status.success() || output.truncated {
        bail!(
            "GitHub request failed or exceeded size bound: {}",
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(2000)
                .collect::<String>()
        );
    }
    Ok(output.stdout)
}

fn is_binary_member(path: &Path, binary_name: &str) -> bool {
    let parts = path
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect::<Vec<_>>();
    parts.len() == 1 && parts[0] == std::path::Component::Normal(std::ffi::OsStr::new(binary_name))
}

fn extract(archive: &[u8], zip: bool) -> Result<Vec<u8>> {
    let binary_name = if zip { "knife.exe" } else { "knife" };
    let mut found = None;
    let mut keep = |reader: &mut dyn Read| -> Result<()> {
        if found.is_some() {
            bail!("duplicate Knife executable in archive");
        }
        let mut bytes = Vec::new();
        reader.take(MAX_BINARY + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_BINARY {
            bail!("invalid executable size");
        }
        found = Some(bytes);
        Ok(())
    };
    if zip {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(archive))?;
        if archive.len() > 1024 {
            bail!("archive member limit exceeded");
        }
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            if is_binary_member(Path::new(entry.name()), binary_name) {
                if !entry.is_file() || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
                    bail!("executable must be a regular file");
                }
                keep(&mut entry)?;
            }
        }
    } else {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(archive));
        let mut total_size = 0u64;
        for (i, entry) in archive.entries()?.enumerate() {
            if i >= 1024 {
                bail!("archive member limit exceeded");
            }
            let mut entry = entry?;
            total_size = total_size
                .checked_add(entry.size())
                .context("archive size overflow")?;
            if total_size > MAX_BINARY {
                bail!("uncompressed archive size bound exceeded");
            }
            if is_binary_member(&entry.path()?, binary_name) {
                if !entry.header().entry_type().is_file() {
                    bail!("executable must be a regular file");
                }
                keep(&mut entry)?;
            }
        }
    }
    found.context("archive contains no root Knife executable")
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn replace_with_backup(executable: &Path, candidate: &Path) -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let parent = executable
        .parent()
        .context("executable has no parent directory")?;
    let backup = parent.join(format!(
        "{}.previous-{stamp}",
        executable
            .file_name()
            .context("missing executable name")?
            .to_string_lossy()
    ));
    let mut saved = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)?;
    std::io::copy(&mut std::fs::File::open(executable)?, &mut saved)?;
    saved.sync_all()?;
    std::fs::set_permissions(&backup, std::fs::metadata(executable)?.permissions())?;
    self_replace::self_replace(candidate).with_context(|| {
        format!(
            "replacement failed; previous executable preserved at {}",
            backup.display()
        )
    })?;
    Ok(backup)
}

pub fn run(check: bool) -> Result<UpdateResult> {
    let target = target()?;
    let raw: Value = serde_json::from_slice(&fetch(API, 2 * 1024 * 1024, 30)?)?;
    let release = release(&raw, target)?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let available = release.version > current;
    let mut result = UpdateResult {
        current_version: current.to_string(),
        latest_version: release.version.to_string(),
        target: target.into(),
        updated: false,
        update_available: available,
        backup: None,
        message: if available {
            format!(
                "Knife {} is available (current {}).",
                release.version, current
            )
        } else {
            format!(
                "Knife {current} is up to date (latest stable {}).",
                release.version
            )
        },
    };
    if check || !available {
        return Ok(result);
    }
    let executable = std::env::current_exe()?.canonicalize()?;
    let parent = executable
        .parent()
        .context("executable has no parent directory")?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path = parent.join(format!(".knife-update-{}-{stamp}", std::process::id()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path).context(
        "cannot stage update beside Knife; ensure its installation directory is writable",
    )?;
    let staging = Staging(path);
    let archive = fetch(&release.url, MAX_BINARY as usize, 180)?;
    if crate::analysis::hashes::sha256_hex(&archive) != release.digest {
        bail!("release archive SHA-256 mismatch; installed Knife was not changed");
    }
    let bytes = extract(&archive, release.name.ends_with(".zip"))?;
    let candidate = staging
        .0
        .join(if cfg!(windows) { "knife.exe" } else { "knife" });
    std::fs::write(&candidate, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))?;
    }
    let version = crate::providers::process::run_process(
        &candidate,
        [OsString::from("--version")],
        Duration::from_secs(5),
        4096,
    )?;
    if !version.status.success()
        || version.truncated
        || String::from_utf8_lossy(&version.stdout).trim() != format!("knife {}", release.version)
    {
        bail!("downloaded executable failed version validation; installed Knife was not changed");
    }
    let backup = replace_with_backup(&executable, &candidate)?;
    result.updated = true;
    result.backup = Some(backup.display().to_string());
    result.message = format!(
        "Updated Knife {current} → {}. Restart Knife to use the new version.",
        release.version
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metadata() -> Value {
        serde_json::json!({"tag_name":"v1.9.0","draft":false,"prerelease":false,"assets":[{"name":"knife-x86_64-unknown-linux-gnu.tgz","browser_download_url":format!("{DOWNLOAD}v1.9.0/knife-x86_64-unknown-linux-gnu.tgz"),"digest":format!("sha256:{}","a".repeat(64))}]})
    }
    #[test]
    fn release_selection_is_platform_exact_and_verified() {
        let raw = metadata();
        assert_eq!(
            release(&raw, "x86_64-unknown-linux-gnu")
                .unwrap()
                .version
                .to_string(),
            "1.9.0"
        );
        assert!(release(&raw, "aarch64-apple-darwin").is_err());
        let mut wrong = raw.clone();
        wrong["assets"][0]["digest"] = Value::Null;
        assert!(release(&wrong, "x86_64-unknown-linux-gnu").is_err());
        wrong = raw.clone();
        wrong["assets"][0]["browser_download_url"] = "https://example.org/knife".into();
        assert!(release(&wrong, "x86_64-unknown-linux-gnu").is_err());
        wrong = raw;
        wrong["prerelease"] = true.into();
        assert!(release(&wrong, "x86_64-unknown-linux-gnu").is_err());
    }
    #[test]
    fn archive_paths_cannot_escape_or_select_nested_executables() {
        assert!(is_binary_member(Path::new("./knife"), "knife"));
        for path in ["../knife", "/knife", "docs/knife", "knife/other"] {
            assert!(!is_binary_member(Path::new(path), "knife"));
        }
    }
    #[test]
    fn tar_extracts_only_executable_and_rejects_duplicates() {
        let build = |duplicate: bool| {
            let mut archive = tar::Builder::new(Vec::new());
            for _ in 0..if duplicate { 2 } else { 1 } {
                let mut header = tar::Header::new_gnu();
                header.set_size(4);
                header.set_mode(0o755);
                header.set_cksum();
                archive
                    .append_data(&mut header, "knife", &b"test"[..])
                    .unwrap();
            }
            let bytes = archive.into_inner().unwrap();
            let mut gzip =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut gzip, &bytes).unwrap();
            gzip.finish().unwrap()
        };
        assert_eq!(extract(&build(false), false).unwrap(), b"test");
        assert!(extract(&build(true), false).is_err());
    }
    #[test]
    fn windows_zip_extracts_root_executable_only() {
        use std::io::Write;
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        archive
            .start_file("docs/knife.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"wrong").unwrap();
        archive
            .start_file("knife.exe", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(b"right").unwrap();
        let bytes = archive.finish().unwrap().into_inner();
        assert_eq!(extract(&bytes, true).unwrap(), b"right");
    }
    #[test]
    fn replacement_preserves_backup() {
        // Replace only an exclusively created child copy of the test executable.
        if let Some(candidate) = std::env::var_os("KNIFE_TEST_REPLACEMENT") {
            let executable = std::env::current_exe().unwrap();
            let backup = replace_with_backup(&executable, Path::new(&candidate)).unwrap();
            assert!(backup.is_file());
            return;
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!("update-test-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        let directory = Staging(path);
        let original = std::env::current_exe().unwrap();
        let child = directory
            .0
            .join(if cfg!(windows) { "child.exe" } else { "child" });
        let candidate = directory.0.join("candidate");
        std::fs::copy(&original, &child).unwrap();
        std::fs::copy(&original, &candidate).unwrap();
        {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .append(true)
                .open(&candidate)
                .unwrap()
                .write_all(b"knife-update-test")
                .unwrap();
        }
        let status = std::process::Command::new(&child)
            .args([
                "--exact",
                "update::tests::replacement_preserves_backup",
                "--nocapture",
            ])
            .env("KNIFE_TEST_REPLACEMENT", &candidate)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::metadata(&child).unwrap().len(),
            std::fs::metadata(&candidate).unwrap().len()
        );
        let backups = std::fs::read_dir(&directory.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".previous-"))
            .collect::<Vec<_>>();
        assert_eq!(backups.len(), 1);
        assert_eq!(
            std::fs::metadata(backups[0].path()).unwrap().len(),
            std::fs::metadata(original).unwrap().len()
        );
    }
    #[test]
    #[ignore = "downloads the live GitHub release archive without installing it"]
    fn live_archive_is_verified_and_extractable() {
        let target = target().unwrap();
        let metadata = serde_json::from_slice(&fetch(API, 2 * 1024 * 1024, 30).unwrap()).unwrap();
        let release = release(&metadata, target).unwrap();
        let archive = fetch(&release.url, MAX_BINARY as usize, 180).unwrap();
        assert_eq!(
            crate::analysis::hashes::sha256_hex(&archive),
            release.digest
        );
        let bytes = extract(&archive, release.name.ends_with(".zip")).unwrap();
        let binary = crate::formats::analyze("downloaded-knife", &bytes).unwrap();
        assert_eq!(
            binary.arch,
            if target.starts_with("aarch64") {
                crate::model::Arch::Aarch64
            } else {
                crate::model::Arch::X86_64
            }
        );
    }
}
