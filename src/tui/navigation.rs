//! Presentation history retains the view that an address was inspected in.

use super::{Focus, RefView};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ViewPositions {
    pub disassembly: usize,
    pub pseudocode: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationLocation {
    pub address: u64,
    /// When true, address is an on-disk file offset. Otherwise it is a
    /// static virtual address. The flag prevents history from conflating the
    /// two spaces while keeping the stored location compact.
    pub file_offset: bool,
    pub cursor: usize,
    pub positions: ViewPositions,
    pub pseudo: bool,
    pub graph: bool,
    pub focus: Focus,
    pub reference_view: RefView,
    pub reference_cursor: usize,
    pub reference_anchor: Option<u64>,
}
