//! Optional external analysis engines exposed through Knife's typed operation
//! boundary. Providers are never required to open a target, and their absence
//! is reported explicitly instead of silently changing Knife's conclusions.

pub mod capa;
pub mod ghidra;
pub(crate) mod process;
pub mod rizin;
pub mod yarax;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub id: &'static str,
    pub name: &'static str,
    pub installed: bool,
    pub executable: Option<String>,
    pub version: Option<String>,
    pub mode: &'static str,
    pub target_execution: bool,
    pub license: &'static str,
    pub operations: Vec<&'static str>,
    pub limitation: Option<String>,
}

pub fn statuses() -> Vec<ProviderStatus> {
    vec![rizin::status(), yarax::status(), capa::status()]
}
