//! Reusable core for Knife front ends and integrations.
//!
//! The `knife` CLI, terminal interface, and external tools all consume these
//! modules instead of maintaining separate analysis paths.

pub mod address;
pub mod analysis;
pub mod api;
pub mod db;
pub mod formats;
pub mod listing;
pub mod mcp;
pub mod model;
pub mod output;
pub mod providers;
#[cfg(test)]
mod robustness;
pub mod tools;
pub mod tui;
pub mod windows;
pub mod workspace;

/// Default instruction-recovery budget used by interactive front ends.
pub const ANALYSIS_BUDGET: usize = 10_000_000;
