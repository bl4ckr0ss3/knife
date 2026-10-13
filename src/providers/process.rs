//! Shared safety boundary for out-of-process static-analysis providers.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(10);
static SNAPSHOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub(crate) struct ProcessOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug)]
struct CacheEntry {
    key: String,
    value: Value,
    bytes: usize,
}

#[derive(Debug)]
pub(super) struct JsonCache {
    entries: VecDeque<CacheEntry>,
    bytes: usize,
    maximum_items: usize,
    maximum_bytes: usize,
}

impl JsonCache {
    pub fn new(maximum_items: usize, maximum_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            maximum_items: maximum_items.max(1),
            maximum_bytes: maximum_bytes.max(1),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<Value> {
        let index = self.entries.iter().position(|entry| entry.key == key)?;
        let entry = self.entries.remove(index)?;
        let value = entry.value.clone();
        self.entries.push_back(entry);
        Some(value)
    }

    pub fn insert(&mut self, key: String, value: Value) {
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            if let Some(previous) = self.entries.remove(index) {
                self.bytes = self.bytes.saturating_sub(previous.bytes);
            }
        }
        let bytes = serde_json::to_vec(&value).map_or(0, |encoded| encoded.len());
        if bytes > self.maximum_bytes {
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes);
        self.entries.push_back(CacheEntry { key, value, bytes });
        while self.entries.len() > self.maximum_items || self.bytes > self.maximum_bytes {
            if let Some(evicted) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(evicted.bytes);
            } else {
                break;
            }
        }
    }
}

pub(super) struct TargetSnapshot {
    path: PathBuf,
}

impl TargetSnapshot {
    pub fn create(provider: &str, bytes: &[u8]) -> Result<Self> {
        if provider.is_empty()
            || !provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(anyhow!("invalid provider snapshot name"));
        }
        for _ in 0..32 {
            let sequence = SNAPSHOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "knife-provider-{provider}-{}-{sequence}.bin",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(bytes).and_then(|_| file.flush()) {
                        let _ = std::fs::remove_file(&path);
                        return Err(error)
                            .context("failed to materialize provider target snapshot");
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).context("failed to create provider target snapshot")
                }
            }
        }
        Err(anyhow!(
            "could not allocate a unique provider target snapshot"
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TargetSnapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) fn run_process<I>(
    executable: &Path,
    args: I,
    deadline: Duration,
    output_limit: usize,
) -> Result<ProcessOutput>
where
    I: IntoIterator<Item = OsString>,
{
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start {}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing child stderr"))?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, output_limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, output_limit));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(anyhow!(
                "external provider exceeded its {} second deadline",
                deadline.as_secs()
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| anyhow!("provider stdout reader panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| anyhow!("provider stderr reader panicked"))??;
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
        truncated: stdout_truncated || stderr_truncated,
    })
}

pub(super) fn read_bounded(
    mut reader: impl Read,
    output_limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let room = output_limit.saturating_sub(kept.len());
        let store = read.min(room);
        kept.write_all(&buffer[..store])?;
        truncated |= store != read;
    }
    Ok((kept, truncated))
}

pub(crate) fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|directory| {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let candidate = directory.join(format!("{name}.exe"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    })
}

pub(super) fn executable_identity(executable: &Path) -> String {
    std::fs::metadata(executable)
        .ok()
        .map(|metadata| {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |duration| duration.as_nanos());
            format!("{}:{}:{modified}", executable.display(), metadata.len())
        })
        .unwrap_or_else(|| executable.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_reader_drains_while_retaining_only_the_bound() {
        let input = vec![0x41; 1024 + 17];
        let (kept, truncated) = read_bounded(input.as_slice(), 1024).unwrap();
        assert_eq!(kept.len(), 1024);
        assert!(truncated);
    }

    #[test]
    fn target_snapshot_is_private_exact_and_removed_on_drop() {
        let path = {
            let snapshot = TargetSnapshot::create("test", b"exact workspace bytes").unwrap();
            assert_eq!(
                std::fs::read(snapshot.path()).unwrap(),
                b"exact workspace bytes"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(snapshot.path())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
            snapshot.path().to_path_buf()
        };
        assert!(!path.exists());
    }

    #[test]
    fn json_cache_is_bounded_and_refreshes_recent_entries() {
        let mut cache = JsonCache::new(2, 1024);
        cache.insert("one".into(), serde_json::json!({"value": 1}));
        cache.insert("two".into(), serde_json::json!({"value": 2}));
        assert_eq!(cache.get("one").unwrap()["value"], 1);
        cache.insert("three".into(), serde_json::json!({"value": 3}));
        assert!(cache.get("two").is_none(), "least-recent entry survived");
        assert_eq!(cache.get("one").unwrap()["value"], 1);
        assert_eq!(cache.get("three").unwrap()["value"], 3);

        let mut byte_bounded = JsonCache::new(4, 8);
        byte_bounded.insert("oversized".into(), serde_json::json!({"too": "large"}));
        assert!(byte_bounded.get("oversized").is_none());
    }
}
