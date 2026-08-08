//! File hashes and the PE import hash (imphash), the classic family-clustering
//! fingerprint.

use crate::model::Binary;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Just the SHA-256, for identifying a file without paying for the other two.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn file_hashes(bytes: &[u8]) -> FileHashes {
    FileHashes {
        md5: hex(&Md5::digest(bytes)),
        sha1: hex(&Sha1::digest(bytes)),
        sha256: hex(&Sha256::digest(bytes)),
    }
}

/// imphash: md5 of the comma-joined, lowercased `dll.function` list in import
/// order, with the extension stripped from the module name. Matches the
/// pefile/VirusTotal definition so values are comparable across tools.
pub fn imphash(bin: &Binary) -> Option<String> {
    if bin.format != crate::model::Format::Pe || bin.imports.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    for lib in &bin.imports {
        let module = lib
            .name
            .rsplit_once('.')
            .map(|(stem, ext)| {
                if matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "dll" | "sys" | "ocx" | "drv"
                ) {
                    stem
                } else {
                    lib.name.as_str()
                }
            })
            .unwrap_or(lib.name.as_str())
            .to_ascii_lowercase();
        for f in &lib.functions {
            parts.push(format!("{}.{}", module, f.to_ascii_lowercase()));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(hex(&Md5::digest(parts.join(",").as_bytes())))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
