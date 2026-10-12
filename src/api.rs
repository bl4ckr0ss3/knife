//! Stable, presentation-neutral query types for Knife front ends.
//!
//! This facade is intentionally narrow. Front ends can migrate one query at a
//! time instead of depending on analysis-engine internals or parsing rendered
//! command output.

use crate::workspace::Session;
use serde::{Deserialize, Serialize};

pub mod binary_summary;
pub mod bookmarks;
pub mod driver_surface;
pub mod edits;
pub mod evidence;
pub mod execution;
pub mod facts;
pub mod graphs;
pub mod kernel_types;
pub mod listing;
pub mod navigation;
pub mod operations;
pub mod paging;
pub mod patches;
pub mod persistence;
pub mod references;
pub mod results;
pub mod risk_signals;
pub mod symbols;
pub mod workspace;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetIdentity {
    pub path: String,
    /// Digest of the unmodified input used to select the analyst database.
    pub sha256: String,
    /// Digest of the bytes actually analyzed after staged patches are applied.
    pub workspace_sha256: String,
    pub staged_patch_bytes: usize,
    pub format: String,
    pub architecture: String,
    pub bits: u32,
    pub size: u64,
    pub image_base: u64,
    /// Container-native entry value. For PE this remains an RVA, matching the
    /// existing `Binary` and front-end contracts.
    pub entry: u64,
    pub subsystem: Option<String>,
    pub is_library: bool,
    pub is_stripped: bool,
    pub functions_recovered: usize,
    pub functions_named: usize,
}

impl TargetIdentity {
    pub fn from_session(session: &Session) -> Self {
        Self {
            path: session.bin.path.clone(),
            sha256: session.db.sha256.clone(),
            workspace_sha256: crate::analysis::hashes::sha256_hex(&session.bytes),
            staged_patch_bytes: session.db.patches.len(),
            format: session.bin.format.label().to_string(),
            architecture: session.bin.arch.label().to_string(),
            bits: session.bin.bits,
            size: session.bin.size,
            image_base: session.bin.image_base,
            entry: session.bin.entry,
            subsystem: session.bin.subsystem.clone(),
            is_library: session.bin.is_lib,
            is_stripped: session.bin.is_stripped,
            functions_recovered: session.an.functions.len(),
            functions_named: session.an.functions.iter().filter(|f| f.named).count(),
        }
    }
}
/// Format-specific header records shared by terminal and external consumers.
pub use crate::formats::elf_headers;
