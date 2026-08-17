//! The interactive view: a function list, a listing, and cross-references,
//! with your names and notes written straight through to the database.
//!
//! State and rendering are kept apart on purpose. Everything that decides what
//! happens lives in `App` and is driven by plain method calls, so the awkward
//! parts (navigation, filtering, the follow-and-return stack) can be tested
//! without a terminal; `render` only ever reads.

mod render;
mod splash;

const GRAPH_NODE_WIDTH: u16 = 7;
const GRAPH_LAYER_HEIGHT: u16 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GraphNode {
    pub index: usize,
    pub layer: usize,
    pub lane: usize,
    pub x: u16,
    pub y: u16,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphLayout {
    pub nodes: Vec<GraphNode>,
    pub width: u16,
    pub height: u16,
}

/// Place a CFG in deterministic top-down layers. The shortest forward distance
/// from entry defines the layer; edges to an existing or earlier layer are back
/// or cross edges and therefore never stretch the canvas indefinitely.
pub(crate) fn graph_layout(
    function: &crate::analysis::engine::Function,
    width: u16,
) -> GraphLayout {
    use std::collections::{BTreeMap, VecDeque};

    let index: BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(i, block)| (block.start, i))
        .collect();
    let mut depth = vec![usize::MAX; function.blocks.len()];
    if !depth.is_empty() {
        depth[0] = 0;
    }
    let mut queue = VecDeque::from([0usize]);
    while let Some(node) = queue.pop_front() {
        if node >= function.blocks.len() {
            continue;
        }
        for successor in &function.blocks[node].succ {
            let Some(&next) = index.get(successor) else {
                continue;
            };
            if depth[next] == usize::MAX {
                depth[next] = depth[node].saturating_add(1);
                queue.push_back(next);
            }
        }
    }
    let fallback = depth
        .iter()
        .filter(|&&d| d != usize::MAX)
        .copied()
        .max()
        .unwrap_or(0)
        + 1;
    for value in &mut depth {
        if *value == usize::MAX {
            *value = fallback;
        }
    }
    let mut layers: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (node, layer) in depth.into_iter().enumerate() {
        layers.entry(layer).or_default().push(node);
    }
    let widest = layers.values().map(Vec::len).max().unwrap_or(1) as u16;
    let canvas_width = width.max(widest.saturating_mul(GRAPH_NODE_WIDTH + 2));
    let mut nodes = Vec::with_capacity(function.blocks.len());
    for (layer, members) in layers {
        let count = members.len() as u16;
        let occupied = count.saturating_mul(GRAPH_NODE_WIDTH);
        let gap = if count > 1 {
            canvas_width.saturating_sub(occupied) / (count + 1)
        } else {
            canvas_width.saturating_sub(GRAPH_NODE_WIDTH) / 2
        };
        let start = gap;
        for (lane, index) in members.into_iter().enumerate() {
            let x = if count > 1 {
                start.saturating_add((lane as u16).saturating_mul(GRAPH_NODE_WIDTH + gap))
            } else {
                start
            };
            nodes.push(GraphNode {
                index,
                layer,
                lane,
                x: x.min(canvas_width.saturating_sub(GRAPH_NODE_WIDTH)),
                y: (layer as u16).saturating_mul(GRAPH_LAYER_HEIGHT),
            });
        }
    }
    nodes.sort_by_key(|node| node.index);
    let height = nodes
        .iter()
        .map(|node| node.y.saturating_add(1))
        .max()
        .unwrap_or(0);
    GraphLayout {
        nodes,
        width: canvas_width,
        height,
    }
}

pub(crate) fn graph_view_offset(layout: &GraphLayout, selected: usize, height: u16) -> u16 {
    let Some(node) = layout.nodes.iter().find(|node| node.index == selected) else {
        return 0;
    };
    node.y
        .saturating_sub(height / 2)
        .min(layout.height.saturating_sub(height))
}

pub(crate) fn graph_horizontal_offset(layout: &GraphLayout, selected: usize, width: u16) -> u16 {
    let Some(node) = layout.nodes.iter().find(|node| node.index == selected) else {
        return 0;
    };
    node.x
        .saturating_add(GRAPH_NODE_WIDTH / 2)
        .saturating_sub(width / 2)
        .min(layout.width.saturating_sub(width))
}

use crate::analysis::engine::{self, Analysis};
use crate::analysis::strings::Located;
use crate::db::Db;
use crate::listing::{self, Line};
use crate::model::Binary;
use anyhow::Result;
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use std::collections::BTreeMap;
use std::io::stdout;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Functions,
    Listing,
    Xrefs,
}

/// What the left pane is showing: the function list, the ranked sink sites, or
/// the kernel-driver summary (devices, IRP dispatch, IOCTLs, primitives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftView {
    Functions,
    Sinks,
    Driver,
    Types,
}

/// Which way the reference pane points: to what is under the cursor (callers),
/// or from the current function (callees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefView {
    To,
    From,
}

/// One row in the reference pane: a jump target, the site shown, its kind (for
/// colour), and the function or import it names.
pub struct XRow {
    pub jump: u64,
    pub site: u64,
    pub kind: &'static str,
    pub label: String,
}

/// One row in the driver pane. `section` rows are non-selectable headings;
/// the rest carry a jump target (`addr`).
pub struct DRow {
    pub label: String,
    pub addr: Option<u64>,
    /// Right-hand cue (xref count, severity, method).
    pub detail: String,
    /// Draw the row in the accent colour (high severity / METHOD_NEITHER).
    pub accent: bool,
    /// Draw the row faint (e.g. a primitive no user-mode path reaches).
    pub faint: bool,
    pub section: bool,
}

/// One row in the whole-program analyst type browser.
pub struct TyRow {
    pub label: String,
    pub detail: String,
    pub addr: Option<u64>,
    pub kind: &'static str,
    pub section: bool,
}

/// What a prompt at the bottom of the screen is collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    Filter,
    Name,
    Note,
    Goto,
    /// Text to find within the current listing.
    Search,
    /// Bind the selected pseudocode field base to a user type.
    Type,
    /// Name the selected field within its bound user type.
    Field,
    /// Set the current function's exact `RETURN (PARAM, ...)` prototype.
    Prototype,
    /// Rename the recovered register, argument, or local on this line.
    Variable,
    /// Stage raw bytes at the selected assembly instruction; empty restores its run.
    Patch,
    /// Merge a portable structure library into this binary database.
    ImportLibrary,
    /// Replace colliding layouts from a portable structure library.
    ReplaceLibrary,
    /// Export this database's portable structure layouts.
    ExportLibrary,
}

impl Ask {
    fn label(self) -> &'static str {
        match self {
            Ask::Filter => "filter",
            Ask::Name => "name",
            Ask::Note => "note",
            Ask::Goto => "goto",
            Ask::Search => "search",
            Ask::Type => "type",
            Ask::Field => "field",
            Ask::Prototype => "prototype",
            Ask::Variable => "variable",
            Ask::Patch => "patch bytes (empty restores)",
            Ask::ImportLibrary => "import library",
            Ask::ReplaceLibrary => "replace from library",
            Ask::ExportLibrary => "export library",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FieldRef {
    function: u64,
    base: String,
    offset: i64,
    type_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VariableRef {
    function: u64,
    base: String,
}

pub struct Prompt {
    pub ask: Ask,
    pub input: String,
    /// The address a name or note will attach to.
    pub at: u64,
    field: Option<FieldRef>,
    variable: Option<VariableRef>,
}

/// What the analysis worker computes: the engine's view, the ranked sink
/// findings, and the literal map. All of it is ready by the time the main
/// view opens, so `App::new` stays cheap.
type WorkResult = (
    crate::analysis::engine::Analysis,
    Vec<crate::analysis::audit::Finding>,
    BTreeMap<u64, Located>,
);

pub struct App {
    // ── the target ──
    pub bin: Binary,
    pub bytes: Vec<u8>,
    pub db: Db,
    pub an: Analysis,
    /// Converts a displayed address into the space the database stores.
    pub base: u64,
    pub title: String,

    // ── function list ──
    /// Indices into `an.functions`, after filtering.
    pub order: Vec<usize>,
    pub sel: usize,
    pub filter: String,

    // ── listing ──
    pub cur: Option<u64>,
    pub lines: Vec<Line>,
    pub cursor: usize,
    /// When set, the listing pane shows decompiled pseudocode for the current
    /// function instead of the disassembly.
    pub pseudo: bool,
    /// Show the current function as navigable CFG basic-block cards.
    pub graph: bool,
    /// The decompiled lines for the current function, rebuilt when it changes
    /// while pseudocode is showing.
    pub pseudo_lines: Vec<crate::analysis::ir::Line>,

    // ── the rest ──
    pub focus: Focus,
    pub prompt: Option<Prompt>,
    pub history: Vec<(u64, usize)>,
    pub status: String,
    pub help: bool,
    pub quit: bool,
    /// Cursor into the cross-reference list (a separate list pane, so it has a
    /// selection of its own like the other two).
    pub xsel: usize,
    /// Terminal size, refreshed before each frame so mouse coordinates from
    /// events can be mapped onto the panes without guessing.
    pub dims: (u16, u16),
    /// The image's literals keyed by virtual address, built once: bytes never
    /// change while the view is open, and rebuilding per navigation is the
    /// kind of cost a big binary makes obvious.
    pub strings: BTreeMap<u64, Located>,

    // ── sinks (attack surface) ──
    /// Ranked sink call sites from the argument-provenance audit, most severe
    /// first, built once.
    pub sinks: Vec<crate::analysis::audit::Finding>,
    /// Whether the left pane shows the function list or the sinks.
    pub left: LeftView,
    /// Cursor into the sinks list.
    pub ssel: usize,
    /// The kernel-driver summary, computed once (linear scans over the entry
    /// and dispatch handlers plus the sink walk), shown when `left` is Driver.
    /// `None` when the target is not a plausible driver, so a non-driver TUI
    /// never pays for the kernel passes.
    pub driver: Option<crate::analysis::driver::DriverReport>,
    /// Cursor into the driver pane rows.
    pub dsel: usize,
    /// Driver-pane filter text (function list filter stays in `filter`).
    pub dsrch: String,
    /// Only show primitives with severity >= this (1 = all).
    pub dminsev: u8,
    /// When set, hide primitives not reachable from the driver entry/handlers.
    pub dreach: bool,
    /// Cursor and filter for the whole-program types/prototypes browser.
    pub tsel: usize,
    pub tysrch: String,

    // ── in-listing search ──
    /// The last text searched for in the listing, so repeating advances.
    pub search: String,

    /// Whether the reference pane shows callers (to) or callees (from).
    pub refview: RefView,

    // ── splash animation ──
    /// Redraw counter, bumped every loop iteration. The splash and the header
    /// spinner derive their phase from it, so they animate without input.
    pub frame: u64,
    /// Whether the animated intro is still playing. Any key clears it.
    pub splash: bool,
}

impl App {
    #[allow(clippy::too_many_arguments)] // the target, its analysis, and the views' caches
    pub fn new(
        bin: Binary,
        bytes: Vec<u8>,
        db: Db,
        an: Analysis,
        sinks: Vec<crate::analysis::audit::Finding>,
        strings: BTreeMap<u64, Located>,
        driver: Option<crate::analysis::driver::DriverReport>,
        title: String,
    ) -> App {
        let base = engine::display_base(&bin);
        let mut app = App {
            bin,
            bytes,
            db,
            an,
            base,
            title,
            order: Vec::new(),
            sel: 0,
            filter: String::new(),
            cur: None,
            lines: Vec::new(),
            cursor: 0,
            pseudo: false,
            graph: false,
            pseudo_lines: Vec::new(),
            focus: Focus::Functions,
            prompt: None,
            history: Vec::new(),
            status: String::new(),
            help: false,
            quit: false,
            xsel: 0,
            dims: (0, 0),
            strings,
            sinks,
            left: LeftView::Functions,
            ssel: 0,
            driver,
            dsel: 0,
            dsrch: String::new(),
            dminsev: 1,
            dreach: false,
            tsel: 0,
            tysrch: String::new(),
            search: String::new(),
            refview: RefView::To,
            frame: 0,
            splash: true,
        };
        app.refilter();
        // Open something immediately: an empty right-hand pane makes the tool
        // look broken rather than ready.
        if let Some(&i) = app.order.first() {
            let addr = app.an.functions[i].addr;
            app.open(addr, false);
        }
        app
    }

    // ── function list ──

    /// Rebuild the visible list from the filter, keeping the selected function
    /// selected when it survives the filter.
    pub fn refilter(&mut self) {
        let keep = self.selected_addr();
        let f = self.filter.to_lowercase();
        self.order = self
            .an
            .functions
            .iter()
            .enumerate()
            .filter(|(_, fun)| f.is_empty() || fun.name.to_lowercase().contains(&f))
            .map(|(i, _)| i)
            .collect();
        self.sel = keep
            .and_then(|a| {
                self.order
                    .iter()
                    .position(|&i| self.an.functions[i].addr == a)
            })
            .unwrap_or(0);
    }

    pub fn selected_addr(&self) -> Option<u64> {
        self.order.get(self.sel).map(|&i| self.an.functions[i].addr)
    }

    pub fn move_sel(&mut self, delta: isize) {
        if self.order.is_empty() {
            return;
        }
        let last = self.order.len() - 1;
        self.sel = self.sel.saturating_add_signed(delta).min(last);
    }

    // ── listing ──

    /// Show a function. `push` records where we were, so `Backspace` returns.
    /// An address that is not inside a recovered function opens as a data
    /// dump instead, which is how following a string operand lands somewhere
    /// you can actually look at its bytes.
    pub fn open(&mut self, addr: u64, push: bool) {
        let target = self
            .an
            .find_function(addr)
            .or_else(|| self.an.function_at(addr))
            .map(|f| f.addr);

        let Some(faddr) = target else {
            if self.an.xrefs_from.contains_key(&addr) || self.is_mapped(addr) {
                if push {
                    if let Some(prev) = self.cur {
                        self.history.push((prev, self.cursor));
                    }
                }
                self.lines = listing::data_view(&self.bin, self.base, &self.bytes, addr);
                self.cur = Some(addr);
                self.cursor = 0;
                self.clamp_xsel();
                return;
            }
            self.status = format!(
                "0x{:x} is not inside a recovered function",
                addr + self.base
            );
            return;
        };

        if push {
            if let Some(prev) = self.cur {
                self.history.push((prev, self.cursor));
            }
        }

        let f = self.an.find_function(faddr).expect("just resolved");
        let graph_cursor = self.graph.then(|| {
            f.blocks
                .iter()
                .position(|block| addr >= block.start && addr < block.end)
                .unwrap_or(0)
        });
        self.lines = listing::function(
            &self.an,
            f,
            &self.db,
            self.base,
            &self.strings,
            self.driver.as_ref().map(|d| &d.listing_hints),
        );
        self.cur = Some(faddr);
        self.clamp_xsel();
        // Land on the requested address, not merely the top of the function.
        self.cursor = self
            .lines
            .iter()
            .position(|l| l.addr() == addr)
            .unwrap_or(0);
        if let Some(block) = graph_cursor {
            self.cursor = block;
        }
        if let Some(p) = self
            .order
            .iter()
            .position(|&i| self.an.functions[i].addr == faddr)
        {
            self.sel = p;
        }
        if self.pseudo {
            self.recompute_pseudo();
            self.cursor = 0;
        }
    }

    /// The number of rows the listing pane is currently showing, which is the
    /// pseudocode length when that view is on and the disassembly length
    /// otherwise. Navigation and mouse mapping both clamp to it.
    pub fn listing_len(&self) -> usize {
        if self.graph {
            self.current_function().map(|f| f.blocks.len()).unwrap_or(0)
        } else if self.pseudo {
            self.pseudo_lines.len()
        } else {
            self.lines.len()
        }
    }

    fn current_function(&self) -> Option<&crate::analysis::engine::Function> {
        self.cur.and_then(|addr| self.an.find_function(addr))
    }

    /// Rebuild the decompiled lines for the current function.
    fn recompute_pseudo(&mut self) {
        self.pseudo_lines.clear();
        if let Some(addr) = self.cur {
            if let Some(f) = self.an.find_function(addr) {
                self.pseudo_lines =
                    crate::analysis::ir::decompile(&self.an, &self.bin, f, &self.strings, &self.db);
            }
        }
    }

    /// Switch the listing pane between disassembly and decompiled pseudocode.
    pub fn toggle_pseudo(&mut self) {
        self.graph = false;
        if !self.pseudo {
            self.recompute_pseudo();
            if self.pseudo_lines.is_empty() {
                self.status = "no pseudocode here: open a recovered function first".into();
                return;
            }
        }
        self.pseudo = !self.pseudo;
        self.cursor = 0;
    }

    /// Switch between the linear listing and the function's control-flow graph.
    pub fn toggle_graph(&mut self) {
        if self.graph {
            self.graph = false;
            self.cursor = 0;
            return;
        }
        if self.current_function().is_none() {
            self.status = "no graph here: open a recovered function first".into();
            return;
        }
        self.pseudo = false;
        self.graph = true;
        self.cursor = 0;
    }

    fn open_graph_block(&mut self) {
        let address = self
            .current_function()
            .and_then(|function| function.blocks.get(self.cursor))
            .map(|block| block.start);
        let Some(address) = address else { return };
        self.graph = false;
        self.pseudo = false;
        self.open(address, false);
        self.focus = Focus::Listing;
    }

    fn move_graph(&mut self, horizontal: isize, vertical: isize) {
        let Some(function) = self.current_function() else {
            return;
        };
        let layout = graph_layout(function, 100);
        let Some(current) = layout.nodes.iter().find(|node| node.index == self.cursor) else {
            return;
        };
        let target = if horizontal != 0 {
            layout
                .nodes
                .iter()
                .filter(|node| node.layer == current.layer)
                .filter(|node| {
                    if horizontal < 0 {
                        node.lane < current.lane
                    } else {
                        node.lane > current.lane
                    }
                })
                .min_by_key(|node| node.lane.abs_diff(current.lane))
        } else {
            let wanted = if vertical < 0 {
                current.layer.checked_sub(1)
            } else {
                Some(current.layer + 1)
            };
            wanted.and_then(|layer| {
                layout
                    .nodes
                    .iter()
                    .filter(|node| node.layer == layer)
                    .min_by_key(|node| node.x.abs_diff(current.x))
            })
        };
        if let Some(target) = target {
            self.cursor = target.index;
        }
    }

    fn graph_block_at_point(&self, x: u16, y: u16, width: u16, height: u16) -> Option<usize> {
        let function = self.current_function()?;
        let layout = graph_layout(function, width);
        let offset = graph_view_offset(&layout, self.cursor, height);
        let horizontal = graph_horizontal_offset(&layout, self.cursor, width);
        layout
            .nodes
            .iter()
            .find(|node| {
                node.y >= offset
                    && node.y - offset == y
                    && x.saturating_add(horizontal) >= node.x
                    && x.saturating_add(horizontal) < node.x.saturating_add(GRAPH_NODE_WIDTH)
            })
            .map(|node| node.index)
    }

    /// Does the address lie inside a mapped section? The data-view entry
    /// test, kept separate from the function-lookup so the two never blur.
    fn is_mapped(&self, addr: u64) -> bool {
        engine::va_to_off(&self.bin, self.base, addr).is_some()
    }

    pub fn back(&mut self) {
        let Some((addr, cursor)) = self.history.pop() else {
            self.status = "nothing to go back to".into();
            return;
        };
        self.open(addr, false);
        self.cursor = cursor.min(self.lines.len().saturating_sub(1));
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let len = self.listing_len();
        if len == 0 {
            return;
        }
        self.cursor = self.cursor.saturating_add_signed(delta).min(len - 1);
    }

    /// The searchable text of listing row `i`, in whichever view is showing.
    fn line_text(&self, i: usize) -> String {
        if self.graph {
            self.current_function()
                .and_then(|function| function.blocks.get(i))
                .map(|block| {
                    let mut text = format!("0x{:x}", block.start + self.base);
                    for instruction in &block.insns {
                        text.push(' ');
                        text.push_str(&instruction.text(self.an.bits, self.an.arch));
                    }
                    for successor in &block.succ {
                        text.push_str(&format!(" 0x{:x}", successor + self.base));
                    }
                    text
                })
                .unwrap_or_default()
        } else if self.pseudo {
            self.pseudo_lines
                .get(i)
                .map(|l| l.text.clone())
                .unwrap_or_default()
        } else {
            match self.lines.get(i) {
                Some(Line::Label { text, .. }) | Some(Line::Data { text, .. }) => text.clone(),
                Some(Line::Insn {
                    mnemonic,
                    operands,
                    annot,
                    ..
                }) => format!("{mnemonic} {operands} {annot:?}"),
                None => String::new(),
            }
        }
    }

    /// Find `text` in the current listing and move the cursor to the next match
    /// after the current line, wrapping. Repeating the same search advances.
    pub fn search_listing(&mut self, text: String) {
        if text.is_empty() {
            return;
        }
        self.search = text.clone();
        let needle = text.to_lowercase();
        let len = self.listing_len();
        let hits: Vec<usize> = (0..len)
            .filter(|&i| self.line_text(i).to_lowercase().contains(&needle))
            .collect();
        if hits.is_empty() {
            self.status = format!("no match for '{text}'");
            return;
        }
        let next = hits
            .iter()
            .find(|&&i| i > self.cursor)
            .copied()
            .unwrap_or(hits[0]);
        self.cursor = next;
        let pos = hits.iter().position(|&i| i == next).unwrap_or(0) + 1;
        self.status = format!("match {pos}/{} for '{text}'", hits.len());
    }

    // ── sinks / driver views ──

    /// Cycle the left pane: functions → sinks → driver → analyst types → back.
    pub fn toggle_sinks(&mut self) {
        self.left = match self.left {
            LeftView::Functions => LeftView::Sinks,
            LeftView::Sinks => LeftView::Driver,
            LeftView::Driver => LeftView::Types,
            LeftView::Types => LeftView::Functions,
        };
        self.focus = Focus::Functions;
        if self.left == LeftView::Types {
            self.clamp_tsel();
            if self
                .type_rows()
                .get(self.tsel)
                .is_some_and(|row| row.section)
            {
                self.move_tsel(1);
            }
        }
        match self.left {
            LeftView::Sinks if self.sinks.is_empty() => {
                self.status = "no sinks found (audit is x86/x64 only)".into()
            }
            LeftView::Driver if !self.driver.as_ref().is_some_and(|d| d.is_driver) => {
                self.status = "not a native-subsystem driver (summary is informational)".into();
            }
            LeftView::Types if self.type_rows().len() == 1 && self.db.is_empty() => {
                self.status = "no analyst types, bindings, or prototypes yet".into();
            }
            _ => {}
        }
    }

    pub fn move_ssel(&mut self, delta: isize) {
        if self.sinks.is_empty() {
            return;
        }
        let last = self.sinks.len() - 1;
        self.ssel = self.ssel.saturating_add_signed(delta).min(last);
    }

    /// Open the call site of the selected sink in the listing.
    pub fn open_sink(&mut self) {
        if let Some(f) = self.sinks.get(self.ssel) {
            let addr = f.addr;
            self.open(addr, true);
            self.focus = Focus::Listing;
        }
    }

    // ── driver pane ──

    /// The flat, ordered rows the driver pane shows. Rebuilt on each render
    /// (like `xref_rows`), so filtering needs no extra cache.
    pub fn driver_rows(&self) -> Vec<DRow> {
        let Some(d) = &self.driver else {
            return vec![DRow {
                label: "not a driver (no kernel surface)".into(),
                addr: None,
                detail: String::new(),
                accent: false,
                faint: true,
                section: false,
            }];
        };
        let q = self.dsrch.to_lowercase();
        let show = |label: &str| q.is_empty() || label.to_lowercase().contains(&q);
        let mut rows: Vec<DRow> = Vec::new();

        if self.dreach && d.primitives.iter().all(|p| !p.reachable) {
            // Nothing would be left; show a single note row instead of a gap.
            rows.push(DRow {
                label: "(no reachable primitives)".into(),
                addr: None,
                detail: String::new(),
                accent: false,
                faint: true,
                section: false,
            });
        }

        if !d.devices.is_empty() {
            rows.push(DRow {
                label: " devices".into(),
                addr: None,
                detail: String::new(),
                accent: false,
                faint: false,
                section: true,
            });
            for dev in &d.devices {
                if show(&dev.name) {
                    rows.push(DRow {
                        label: dev.name.clone(),
                        addr: Some(dev.addr),
                        detail: if dev.created {
                            format!("{} xref · created", dev.xrefs)
                        } else {
                            format!("{} xref", dev.xrefs)
                        },
                        accent: dev.created || dev.xrefs > 0,
                        faint: dev.xrefs == 0 && !dev.created,
                        section: false,
                    });
                }
            }
        }

        if !d.irp.is_empty() {
            rows.push(DRow {
                label: " irp dispatch".into(),
                addr: None,
                detail: String::new(),
                accent: false,
                faint: false,
                section: true,
            });
            for h in &d.irp {
                if show(h.derived.as_str()) || show(h.name.as_str()) {
                    rows.push(DRow {
                        label: h.derived.clone(),
                        addr: Some(h.addr),
                        detail: format!("0x{:02x} {}", h.major, h.name),
                        accent: matches!(h.major, 14 | 15),
                        faint: false,
                        section: false,
                    });
                }
            }
        }

        if !d.ioctls.is_empty() {
            rows.push(DRow {
                label: " ioctls".into(),
                addr: None,
                detail: String::new(),
                accent: false,
                faint: false,
                section: true,
            });
            for i in &d.ioctls {
                let l = format!("0x{:08x} dev{} {}", i.code, i.device_type, i.method);
                if show(&l) {
                    rows.push(DRow {
                        label: l,
                        addr: Some(i.addr),
                        detail: format!("access {}", i.access),
                        accent: i.method_code == 3,
                        faint: false,
                        section: false,
                    });
                }
            }
        }

        rows.push(DRow {
            label: " primitives".into(),
            addr: None,
            detail: format!("({})", d.primitives.len()),
            accent: false,
            faint: false,
            section: true,
        });
        for p in &d.primitives {
            if p.severity < self.dminsev {
                continue;
            }
            if self.dreach && !p.reachable {
                continue;
            }
            // One row per primitive, not per call site: a driver like clfs has
            // hundreds of ZwClose/KeWait sites and the pane must stay bound by
            // the API count, not the site count. Enter still lands on a real
            // call (the first site); the count is in the detail.
            let Some(first) = p.sites.first() else {
                continue;
            };
            let fname = first.in_func.clone().unwrap_or_else(|| "?".into());
            let l = format!("{} @{}", p.api, fname);
            if show(&l) {
                rows.push(DRow {
                    label: l,
                    addr: Some(first.from),
                    detail: format!(
                        "sev{} {} · {} site{}",
                        p.severity,
                        p.class,
                        p.sites.len(),
                        if p.sites.len() == 1 { "" } else { "s" }
                    ),
                    accent: p.severity >= 3,
                    faint: !p.reachable,
                    section: false,
                });
            }
        }
        rows
    }

    fn driver_row_addr(&self, sel: usize) -> Option<u64> {
        self.driver_rows().get(sel).and_then(|r| r.addr)
    }

    fn clamp_dsel(&mut self) {
        let n = self.driver_rows().len();
        self.dsel = self.dsel.min(n.saturating_sub(1));
    }

    pub fn move_dsel(&mut self, delta: isize) {
        let rows = self.driver_rows();
        if rows.is_empty() {
            return;
        }
        // Header rows are not selectable: skip over them.
        let mut next = self.dsel;
        let dir = if delta >= 0 { 1 } else { -1 };
        for _ in 0..rows.len() + 1 {
            next = ((next as isize + dir).rem_euclid(rows.len() as isize)) as usize;
            if !rows[next].section {
                self.dsel = next;
                return;
            }
        }
    }

    pub fn open_driver(&mut self) {
        if let Some(addr) = self.driver_row_addr(self.dsel) {
            self.open(addr, true);
            self.focus = Focus::Listing;
        }
    }

    // ── analyst types / prototypes pane ──

    pub fn type_rows(&self) -> Vec<TyRow> {
        let query = self.tysrch.to_lowercase();
        let matches = |label: &str, detail: &str| {
            query.is_empty()
                || label.to_lowercase().contains(&query)
                || detail.to_lowercase().contains(&query)
        };
        let function_name = |address: u64| {
            self.an
                .find_function(address)
                .map(|function| function.name.clone())
                .unwrap_or_else(|| format!("sub_{address:x}"))
        };
        let mut rows = Vec::new();

        let mut prototypes = Vec::new();
        for (&function, prototype) in &self.db.prototypes {
            let label = function_name(function);
            let detail = format!("{} ({})", prototype.returns, prototype.params.join(", "));
            if matches(&label, &detail) {
                prototypes.push(TyRow {
                    label,
                    detail,
                    addr: Some(function),
                    kind: "prototype",
                    section: false,
                });
            }
        }
        push_type_group(&mut rows, "PROTOTYPES", prototypes);

        let mut layouts = Vec::new();
        for (type_name, fields) in &self.db.fields {
            let detail = fields
                .iter()
                .map(|(offset, field)| format!("{offset:+#x} {field}"))
                .collect::<Vec<_>>()
                .join(" · ");
            if matches(type_name, &detail) {
                layouts.push(TyRow {
                    label: type_name.clone(),
                    detail: if detail.is_empty() {
                        "empty layout".into()
                    } else {
                        detail
                    },
                    addr: None,
                    kind: "layout",
                    section: false,
                });
            }
        }
        push_type_group(&mut rows, "STRUCTURES", layouts);

        let mut bindings = Vec::new();
        for ((function, base), type_name) in &self.db.bindings {
            let label = format!("{}:{base}", function_name(*function));
            let detail = format!("{type_name} *");
            if matches(&label, &detail) {
                bindings.push(TyRow {
                    label,
                    detail,
                    addr: Some(*function),
                    kind: "binding",
                    section: false,
                });
            }
        }
        push_type_group(&mut rows, "BINDINGS", bindings);

        let mut variables = Vec::new();
        for ((function, base), name) in &self.db.variables {
            let label = format!("{}:{base}", function_name(*function));
            if matches(&label, name) {
                variables.push(TyRow {
                    label,
                    detail: name.clone(),
                    addr: Some(*function),
                    kind: "variable",
                    section: false,
                });
            }
        }
        push_type_group(&mut rows, "VARIABLES", variables);

        if rows.is_empty() {
            rows.push(TyRow {
                label: if query.is_empty() {
                    "no analyst types yet".into()
                } else {
                    format!("no type fact matches '{query}'")
                },
                detail: "p/l edit prototypes/variables; t/e edit structures".into(),
                addr: None,
                kind: "empty",
                section: false,
            });
        }
        rows
    }

    fn clamp_tsel(&mut self) {
        self.tsel = self.tsel.min(self.type_rows().len().saturating_sub(1));
    }

    pub fn move_tsel(&mut self, delta: isize) {
        let rows = self.type_rows();
        if rows.is_empty() {
            return;
        }
        let direction = if delta >= 0 { 1 } else { -1 };
        let mut next = self.tsel.min(rows.len() - 1);
        for _ in 0..rows.len() + 1 {
            next = ((next as isize + direction).rem_euclid(rows.len() as isize)) as usize;
            if !rows[next].section {
                self.tsel = next;
                return;
            }
        }
    }

    pub fn open_type(&mut self) {
        let rows = self.type_rows();
        let Some(row) = rows.get(self.tsel) else {
            return;
        };
        if let Some(address) = row.addr {
            self.open(address, true);
            self.focus = Focus::Listing;
        } else {
            self.status = format!("{}: {}", row.label, row.detail);
        }
    }

    /// Route a typed filter to whichever pane is focused.
    fn set_filter(&mut self, text: String) {
        match self.left {
            LeftView::Driver => {
                self.dsrch = text;
                self.clamp_dsel();
            }
            LeftView::Types => {
                self.tysrch = text;
                self.clamp_tsel();
            }
            _ => {
                self.filter = text;
                self.refilter();
            }
        }
    }

    /// The address the cursor is on, which is what a name, note, or
    /// cross-reference lookup applies to.
    pub fn cursor_addr(&self) -> Option<u64> {
        match self.focus {
            // A pseudocode line has no address of its own, so naming and noting
            // in that view apply to the function as a whole.
            Focus::Listing if self.graph => self
                .current_function()
                .and_then(|function| function.blocks.get(self.cursor))
                .map(|block| block.start),
            Focus::Listing if self.pseudo => self.cur,
            Focus::Listing => self.lines.get(self.cursor).map(Line::addr),
            Focus::Functions => match self.left {
                LeftView::Driver => self.driver_row_addr(self.dsel),
                LeftView::Types => self.type_rows().get(self.tsel).and_then(|row| row.addr),
                _ => self.selected_addr(),
            },
            // Naming/noting want the address of interest; the xrefs pane
            // selection is a *reference away*, so it reports nothing here.
            Focus::Xrefs => None,
        }
    }

    /// Follow the call or branch under the cursor; an instruction with no
    /// control-flow target falls back to its data operand, opening the
    /// referenced bytes when they are not code.
    pub fn follow(&mut self) {
        if self.pseudo {
            self.status = "switch to the disassembly (d) to follow a call".into();
            return;
        }
        let line = self.lines.get(self.cursor);
        if let Some(t) = line.and_then(Line::target) {
            // An import slot has a name but no body; say so rather than failing.
            if self.an.find_function(t).is_none() && self.an.function_at(t).is_none() {
                self.status = match self.an.imports.get(&t) {
                    Some(n) => format!("{n} is imported; there is no body to show"),
                    None => format!("0x{:x} is not a recovered function", t + self.base),
                };
                return;
            }
            self.open(t, true);
            self.focus = Focus::Listing;
            return;
        }

        // No control-flow target: a data operand, if the engine found one.
        let at = line.map(Line::addr).unwrap_or(0);
        let to = match self.an.xrefs_from.get(&at).map(|r| r.first().map(|r| r.to)) {
            Some(Some(t)) => t,
            _ => {
                self.status = "nothing to follow here".into();
                return;
            }
        };
        self.open(to, true);
        self.focus = Focus::Listing;
    }

    /// The address the reference pane keys off: whatever is under the cursor.
    pub fn xref_at(&self) -> u64 {
        self.cursor_addr().or(self.cur).unwrap_or(0)
    }

    /// The name of a call/reference site: its function, with an offset when the
    /// site is inside one rather than at its head.
    fn site_name(&self, addr: u64) -> String {
        match self.an.function_at(addr) {
            Some(fun) => {
                let off = addr.saturating_sub(fun.addr);
                if off == 0 {
                    fun.name.clone()
                } else {
                    format!("{}+0x{off:x}", fun.name)
                }
            }
            None => "-".into(),
        }
    }

    /// The reference pane's rows: callers of what is under the cursor, or the
    /// callees of the current function.
    pub fn xref_rows(&self) -> Vec<XRow> {
        match self.refview {
            RefView::To => {
                let at = self.xref_at();
                self.an
                    .xrefs_to
                    .get(&at)
                    .map(|v| {
                        v.iter()
                            .map(|x| XRow {
                                jump: x.from,
                                site: x.from,
                                kind: x.kind.label(),
                                label: self.site_name(x.from),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            }
            RefView::From => {
                let mut seen = std::collections::BTreeSet::new();
                let mut rows = Vec::new();
                for l in &self.lines {
                    let Some(t) = l.target() else { continue };
                    if !seen.insert(t) {
                        continue;
                    }
                    let name = self
                        .an
                        .find_function(t)
                        .map(|f| f.name.clone())
                        .or_else(|| self.an.imports.get(&t).cloned());
                    if let Some(name) = name {
                        rows.push(XRow {
                            jump: t,
                            site: l.addr(),
                            kind: "call",
                            label: name,
                        });
                    }
                }
                rows
            }
        }
    }

    pub fn clamp_xsel(&mut self) {
        let n = self.xref_rows().len();
        self.xsel = if n == 0 { 0 } else { self.xsel.min(n - 1) };
    }

    pub fn move_xsel(&mut self, delta: isize) {
        let n = self.xref_rows().len();
        if n == 0 {
            self.xsel = 0;
            return;
        }
        self.xsel = self.xsel.saturating_add_signed(delta).min(n - 1);
    }

    pub fn toggle_refs(&mut self) {
        self.refview = match self.refview {
            RefView::To => RefView::From,
            RefView::From => RefView::To,
        };
        self.xsel = 0;
    }

    /// Follow the reference under the cursor: jump to where it points.
    pub fn jump_xref(&mut self) {
        let rows = self.xref_rows();
        let Some(row) = rows.get(self.xsel) else {
            self.status = "no reference under the cursor".into();
            return;
        };
        let t = row.jump;
        if self.an.function_at(t).is_none() && self.an.find_function(t).is_none() {
            self.status = match self.an.imports.get(&t) {
                Some(n) => format!("{n} is imported; there is no body to show"),
                None => format!("0x{:x} is not in a recovered function", t + self.base),
            };
            return;
        }
        self.open(t, true);
        self.focus = Focus::Listing;
    }

    // ── annotations ──

    #[cfg(test)]
    fn commit(&mut self, ask: Ask, at: u64, text: String) {
        self.commit_with_context(ask, at, text, None, None);
    }

    fn commit_with_context(
        &mut self,
        ask: Ask,
        at: u64,
        text: String,
        field: Option<FieldRef>,
        variable: Option<VariableRef>,
    ) {
        let stored = at.wrapping_sub(self.base);
        match ask {
            Ask::Filter => {
                self.set_filter(text);
            }
            Ask::Goto => {
                match parse_addr(&text)
                    .map(|v| vec![v])
                    .filter(|v| !v.is_empty())
                    .or_else(|| Some(self.an.resolve(&text, None)))
                    .filter(|v| !v.is_empty())
                {
                    Some(v) => self.open(v[0], true),
                    None => self.status = format!("no symbol or address '{text}'"),
                }
            }
            Ask::Search => self.search_listing(text),
            Ask::Name => {
                if text.is_empty() {
                    let (n, _) = self.db.clear(stored);
                    self.status = match n {
                        Some(old) => format!("cleared the name {old}"),
                        None => "nothing to clear".into(),
                    };
                } else {
                    self.db.set_name(stored, &text);
                    self.status = format!("named 0x{at:x} {text}");
                }
                self.save();
                self.rename_in_place(at);
            }
            Ask::Note => {
                if text.is_empty() {
                    self.db.clear(stored);
                    self.status = "cleared the note".into();
                } else {
                    self.db.set_note(stored, &text);
                    self.status = format!("noted 0x{at:x}");
                }
                self.save();
                self.relist();
            }
            Ask::Type => {
                let Some(field) = field else {
                    self.status = "no field selected".into();
                    return;
                };
                if text.is_empty() {
                    self.db.clear_binding(field.function, &field.base);
                    self.status = format!("cleared the type on {}", field.base);
                } else if let Err(error) = self.db.bind_type(field.function, &field.base, &text) {
                    self.status = error.to_string();
                    return;
                } else {
                    self.status = format!("bound {} as {text}", field.base);
                }
                self.save();
                self.recompute_pseudo();
                self.cursor = self.cursor.min(self.pseudo_lines.len().saturating_sub(1));
            }
            Ask::Field => {
                let Some(field) = field else {
                    self.status = "no field selected".into();
                    return;
                };
                let Some(type_name) = field.type_name else {
                    self.status = "bind the field base to a type with t first".into();
                    return;
                };
                if text.is_empty() {
                    self.db.clear_field(&type_name, field.offset);
                    self.status = format!("cleared {type_name}{:+#x}", field.offset);
                } else {
                    let (name, data_type) = match parse_field_definition(&text) {
                        Ok(definition) => definition,
                        Err(error) => {
                            self.status = error;
                            return;
                        }
                    };
                    if let Err(error) = self.db.set_typed_field(
                        &type_name,
                        field.offset,
                        &name,
                        data_type.as_deref(),
                    ) {
                        self.status = error.to_string();
                        return;
                    }
                    self.status = format!("defined {type_name}{:+#x} {text}", field.offset);
                }
                self.save();
                self.recompute_pseudo();
                self.cursor = self.cursor.min(self.pseudo_lines.len().saturating_sub(1));
            }
            Ask::Prototype => {
                if text.trim().is_empty() {
                    self.db.clear_prototype(stored);
                    self.status = "cleared the function prototype".into();
                } else {
                    let (returns, params) = match parse_prototype(&text) {
                        Ok(prototype) => prototype,
                        Err(error) => {
                            self.status = error;
                            return;
                        }
                    };
                    if let Err(error) = self.db.set_prototype(stored, &returns, &params) {
                        self.status = error.to_string();
                        return;
                    }
                    self.status = format!("prototype {returns} ({})", params.join(", "));
                }
                self.save();
                self.recompute_pseudo();
                self.cursor = self.cursor.min(self.pseudo_lines.len().saturating_sub(1));
            }
            Ask::Variable => {
                let Some(variable) = variable else {
                    self.status = "no pseudocode variable selected".into();
                    return;
                };
                if text.trim().is_empty() {
                    self.db.clear_variable(variable.function, &variable.base);
                    self.status = format!("cleared the alias on {}", variable.base);
                } else if let Err(error) =
                    self.db
                        .set_variable(variable.function, &variable.base, text.trim())
                {
                    self.status = error.to_string();
                    return;
                } else {
                    self.status = format!("renamed {} as {}", variable.base, text.trim());
                }
                self.save();
                self.recompute_pseudo();
                self.cursor = self.cursor.min(self.pseudo_lines.len().saturating_sub(1));
            }
            Ask::Patch => {
                let Some(offset) = engine::va_to_off(&self.bin, self.base, at) else {
                    self.status = format!("address 0x{at:x} is not backed by file bytes");
                    return;
                };
                let patch_offset = offset as u64;
                let mut next_db = self.db.clone();
                if text.trim().is_empty() {
                    let restored = next_db.clear_patch_run_at(patch_offset);
                    if restored.is_empty() {
                        self.status = "no staged patch covers this instruction".into();
                        return;
                    }
                    if let Err(error) = next_db.save() {
                        self.status = format!("could not save restored bytes: {error:#}");
                        return;
                    }
                    for &(at, original) in &restored {
                        if let Some(byte) = usize::try_from(at)
                            .ok()
                            .and_then(|index| self.bytes.get_mut(index))
                        {
                            *byte = original;
                        }
                    }
                    self.db = next_db;
                    self.refresh_analysis();
                    self.status = format!(
                        "restored {} staged byte{}",
                        restored.len(),
                        plural_suffix(restored.len())
                    );
                } else {
                    let replacement = match crate::db::parse_patch_bytes(text.trim()) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            self.status = error.to_string();
                            return;
                        }
                    };
                    if let Err(error) = next_db.stage_patch(&self.bytes, patch_offset, &replacement)
                    {
                        self.status = error.to_string();
                        return;
                    }
                    if let Err(error) = next_db.save() {
                        self.status = format!("could not save patch: {error:#}");
                        return;
                    }
                    let start = offset;
                    self.bytes[start..start + replacement.len()].copy_from_slice(&replacement);
                    self.db = next_db;
                    self.refresh_analysis();
                    self.status = format!(
                        "staged {} byte{} at file offset {offset:#x}",
                        replacement.len(),
                        plural_suffix(replacement.len())
                    );
                }
            }
            Ask::ImportLibrary | Ask::ReplaceLibrary => {
                if text.trim().is_empty() {
                    self.status = "give a type-library JSON path".into();
                    return;
                }
                let replace = ask == Ask::ReplaceLibrary;
                match self
                    .db
                    .import_type_library(std::path::Path::new(text.trim()), replace)
                {
                    Ok(summary) => {
                        if let Err(error) = self.db.save() {
                            self.status =
                                format!("imported in memory but could not save: {error:#}");
                            return;
                        }
                        self.recompute_pseudo();
                        self.clamp_tsel();
                        self.status = format!(
                            "{} {} type{} / {} field{} from {}",
                            if replace { "replaced" } else { "imported" },
                            summary.types,
                            if summary.types == 1 { "" } else { "s" },
                            summary.fields,
                            if summary.fields == 1 { "" } else { "s" },
                            text.trim()
                        );
                    }
                    Err(error) => self.status = format!("library import failed: {error:#}"),
                }
            }
            Ask::ExportLibrary => {
                if text.trim().is_empty() {
                    self.status = "give an export JSON path".into();
                    return;
                }
                match self
                    .db
                    .export_type_library(std::path::Path::new(text.trim()))
                {
                    Ok(summary) => {
                        self.status = format!(
                            "exported {} type{} / {} field{} to {}",
                            summary.types,
                            if summary.types == 1 { "" } else { "s" },
                            summary.fields,
                            if summary.fields == 1 { "" } else { "s" },
                            text.trim()
                        );
                    }
                    Err(error) => self.status = format!("library export failed: {error:#}"),
                }
            }
        }
    }

    fn save(&mut self) {
        if let Err(e) = self.db.save() {
            self.status = format!("could not save: {e:#}");
        }
    }

    /// Apply a rename without re-running the engine when we can, because a full
    /// re-analysis of a large image is slow enough to feel like a hang.
    fn rename_in_place(&mut self, at: u64) {
        let name = self.db.names.get(&at.wrapping_sub(self.base)).cloned();
        let known = self.an.find_function(at).is_some();

        match (name, known) {
            (Some(n), true) => {
                self.an.names.insert(at, n.clone());
                if let Some(f) = self.an.functions.iter_mut().find(|f| f.addr == at) {
                    f.name = n;
                    f.named = true;
                }
            }
            (None, true) => {
                self.an.names.remove(&at);
                if let Some(f) = self.an.functions.iter_mut().find(|f| f.addr == at) {
                    f.name = format!("sub_{at:x}");
                    f.named = false;
                }
            }
            // Naming an address with no function there is a request to find
            // one, and only the engine can do that.
            _ => self.reanalyze(),
        }
        self.refilter();
        self.relist();
    }

    fn relist(&mut self) {
        if let Some(addr) = self.cur {
            if let Some(f) = self.an.find_function(addr) {
                self.lines = listing::function(
                    &self.an,
                    f,
                    &self.db,
                    self.base,
                    &self.strings,
                    self.driver.as_ref().map(|d| &d.listing_hints),
                );
            } else if engine::va_to_off(&self.bin, self.base, addr).is_some() {
                self.lines = listing::data_view(&self.bin, self.base, &self.bytes, addr);
            }
        }
        if self.pseudo {
            self.recompute_pseudo();
        }
        self.cursor = self.cursor.min(self.listing_len().saturating_sub(1));
    }

    pub fn reanalyze(&mut self) {
        self.an = engine::analyze(&self.bin, &self.bytes, 2_000_000, &self.db);
        self.refilter();
        self.relist();
    }

    /// Rebuild every view derived from target bytes after an interactive edit.
    fn refresh_analysis(&mut self) {
        self.an = engine::analyze(&self.bin, &self.bytes, crate::ANALYSIS_BUDGET, &self.db);
        self.strings = listing::string_map(&self.bin, &self.bytes, self.base);
        self.sinks = crate::analysis::audit::run(&self.an, &self.bin, &self.bytes);
        self.sinks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.reachable.cmp(&a.reachable))
                .then(a.addr.cmp(&b.addr))
        });
        self.driver = crate::analysis::driver::plausibly_a_driver(&self.bin).then(|| {
            crate::analysis::driver::report(&self.bin, &self.bytes, &self.an, &self.strings)
        });
        self.refilter();
        self.relist();
    }

    // ── input ──

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return; // Windows reports releases too; acting on both double-fires
        }

        // The splash swallows the first key so it cannot quit or navigate.
        if self.splash {
            self.splash = false;
            return;
        }

        if let Some(p) = &mut self.prompt {
            match key.code {
                KeyCode::Esc => self.prompt = None,
                KeyCode::Enter => {
                    let p = self.prompt.take().expect("checked above");
                    self.commit_with_context(p.ask, p.at, p.input, p.field, p.variable);
                }
                KeyCode::Backspace => {
                    p.input.pop();
                    // A filter should react as it is typed.
                    if p.ask == Ask::Filter {
                        let text = p.input.clone();
                        self.set_filter(text);
                    }
                }
                KeyCode::Char(c) => {
                    p.input.push(c);
                    if p.ask == Ask::Filter {
                        let text = p.input.clone();
                        self.set_filter(text);
                    }
                }
                _ => {}
            }
            return;
        }

        if self.help {
            self.help = false;
            return;
        }

        self.status.clear();
        let page = 20isize;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Functions => Focus::Listing,
                    Focus::Listing => Focus::Xrefs,
                    Focus::Xrefs => Focus::Functions,
                }
            }
            KeyCode::Left if self.focus == Focus::Listing && self.graph => self.move_graph(-1, 0),
            KeyCode::Right if self.focus == Focus::Listing && self.graph => self.move_graph(1, 0),
            KeyCode::Down | KeyCode::Char('j') if self.focus == Focus::Listing && self.graph => {
                self.move_graph(0, 1)
            }
            KeyCode::Up | KeyCode::Char('k') if self.focus == Focus::Listing && self.graph => {
                self.move_graph(0, -1)
            }
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::PageDown => self.step(page),
            KeyCode::PageUp => self.step(-page),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Enter => match self.focus {
                Focus::Functions => match self.left {
                    LeftView::Sinks => self.open_sink(),
                    LeftView::Driver => self.open_driver(),
                    LeftView::Types => self.open_type(),
                    LeftView::Functions => {
                        if let Some(a) = self.selected_addr() {
                            self.open(a, true);
                            self.focus = Focus::Listing;
                        }
                    }
                },
                Focus::Listing if self.graph => self.open_graph_block(),
                Focus::Listing => self.follow(),
                Focus::Xrefs => self.jump_xref(),
            },
            KeyCode::Backspace => self.back(),
            // `/` filters the function list, but searches within the code when
            // the listing is focused.
            KeyCode::Char('/') if self.focus == Focus::Listing => self.ask(Ask::Search),
            KeyCode::Char('/') => self.ask(Ask::Filter),
            KeyCode::Char('g') => self.ask(Ask::Goto),
            KeyCode::Char('n') => self.ask(Ask::Name),
            KeyCode::Char('c') => self.ask(Ask::Note),
            KeyCode::Char('t') if self.focus == Focus::Listing && self.pseudo => {
                self.ask(Ask::Type)
            }
            KeyCode::Char('e') if self.focus == Focus::Listing && self.pseudo => {
                self.ask(Ask::Field)
            }
            KeyCode::Char('p') if self.focus == Focus::Listing && self.pseudo => {
                self.ask(Ask::Prototype)
            }
            KeyCode::Char('l') if self.focus == Focus::Listing && self.pseudo => {
                self.ask(Ask::Variable)
            }
            KeyCode::Char('P') if self.focus == Focus::Listing && !self.pseudo && !self.graph => {
                self.ask(Ask::Patch)
            }
            KeyCode::Char('I')
                if self.focus == Focus::Functions && self.left == LeftView::Types =>
            {
                self.ask(Ask::ImportLibrary)
            }
            KeyCode::Char('R')
                if self.focus == Focus::Functions && self.left == LeftView::Types =>
            {
                self.ask(Ask::ReplaceLibrary)
            }
            KeyCode::Char('E')
                if self.focus == Focus::Functions && self.left == LeftView::Types =>
            {
                self.ask(Ask::ExportLibrary)
            }
            KeyCode::Char('s') => self.toggle_sinks(),
            KeyCode::Char('v') => self.toggle_sinks(),
            KeyCode::Char('w') => {
                self.dreach = !self.dreach;
                self.clamp_dsel();
                self.status = format!(
                    "driver pane: {} reachable primitives",
                    if self.dreach { "only" } else { "all" }
                );
            }
            KeyCode::Char('3') => {
                self.dminsev = if self.dminsev >= 3 { 1 } else { 3 };
                self.clamp_dsel();
                self.status = format!(
                    "driver pane: severity {} {}",
                    if self.dminsev >= 3 { ">= 3" } else { "any" },
                    if self.dminsev >= 3 {
                        "(critical primitives only)"
                    } else {
                        "(all)"
                    }
                );
            }
            KeyCode::Char('x') => self.toggle_refs(),
            KeyCode::Char('d') => {
                self.toggle_pseudo();
                self.focus = Focus::Listing;
            }
            KeyCode::Char('f') => {
                self.toggle_graph();
                self.focus = Focus::Listing;
            }
            KeyCode::Char('r') => {
                self.reanalyze();
                self.status = "re-analysed".into();
            }
            _ => {}
        }
    }

    fn step(&mut self, delta: isize) {
        match self.focus {
            Focus::Functions => match self.left {
                LeftView::Functions => self.move_sel(delta),
                LeftView::Sinks => self.move_ssel(delta),
                LeftView::Driver => self.move_dsel(delta),
                LeftView::Types => self.move_tsel(delta),
            },
            Focus::Listing => self.move_cursor(delta),
            Focus::Xrefs => self.move_xsel(delta),
        }
    }

    fn selected_field_ref(&self) -> Option<FieldRef> {
        if !self.pseudo {
            return None;
        }
        let function = self
            .current_function()?
            .addr
            .wrapping_sub(self.an.display_base);
        parse_field_ref(
            self.pseudo_lines.get(self.cursor)?.text.as_str(),
            function,
            &self.db,
        )
    }

    fn selected_variable_ref(&self) -> Option<VariableRef> {
        if !self.pseudo {
            return None;
        }
        let function = self
            .current_function()?
            .addr
            .wrapping_sub(self.an.display_base);
        let text = &self.pseudo_lines.get(self.cursor)?.text;
        if let Some(field) = parse_field_ref(text, function, &self.db) {
            return Some(VariableRef {
                function,
                base: field.base,
            });
        }
        if let Some(((_, base), _)) = self
            .db
            .variables
            .iter()
            .find(|((owner, _), alias)| *owner == function && contains_identifier(text, alias))
        {
            return Some(VariableRef {
                function,
                base: base.clone(),
            });
        }
        text.split(|ch: char| ch != '_' && !ch.is_ascii_alphanumeric())
            .find(|token| is_recovered_variable(token))
            .map(|base| VariableRef {
                function,
                base: base.to_string(),
            })
    }

    fn ask(&mut self, ask: Ask) {
        let at = if matches!(ask, Ask::Prototype | Ask::Variable) {
            self.current_function()
                .map(|function| function.addr + self.base)
                .unwrap_or(0)
        } else {
            self.cursor_addr().unwrap_or(0)
        };
        // Editing an existing value should start from it rather than blank.
        let stored = at.wrapping_sub(self.base);
        let field = if matches!(ask, Ask::Type | Ask::Field) {
            let Some(field) = self.selected_field_ref() else {
                self.status = "put the pseudocode cursor on a field access first".into();
                return;
            };
            if ask == Ask::Field && field.type_name.is_none() {
                self.status = "bind the field base to a type with t first".into();
                return;
            }
            Some(field)
        } else {
            None
        };
        let variable = if ask == Ask::Variable {
            let Some(variable) = self.selected_variable_ref() else {
                self.status = "put the pseudocode cursor on a variable first".into();
                return;
            };
            Some(variable)
        } else {
            None
        };
        if ask == Ask::Patch && !matches!(self.lines.get(self.cursor), Some(Line::Insn { .. })) {
            self.status = "put the assembly cursor on an instruction first".into();
            return;
        }
        let input = match ask {
            Ask::Filter => match self.left {
                LeftView::Driver => self.dsrch.clone(),
                LeftView::Types => self.tysrch.clone(),
                _ => self.filter.clone(),
            },
            Ask::Name => self.db.names.get(&stored).cloned().unwrap_or_default(),
            Ask::Note => self.db.notes.get(&stored).cloned().unwrap_or_default(),
            Ask::Goto => String::new(),
            // Prefilled with the last search so pressing `/`↵ repeats it.
            Ask::Search => self.search.clone(),
            Ask::Type => field
                .as_ref()
                .and_then(|field| field.type_name.clone())
                .unwrap_or_default(),
            Ask::Field => field
                .as_ref()
                .and_then(|field| {
                    field.type_name.as_ref().and_then(|type_name| {
                        self.db
                            .fields
                            .get(type_name)
                            .and_then(|fields| fields.get(&field.offset))
                            .map(ToString::to_string)
                    })
                })
                .unwrap_or_default(),
            Ask::Prototype => self
                .db
                .prototype(stored)
                .map(|prototype| format!("{} ({})", prototype.returns, prototype.params.join(", ")))
                .unwrap_or_default(),
            Ask::Variable => variable
                .as_ref()
                .and_then(|variable| {
                    self.db
                        .variable_name(variable.function, &variable.base)
                        .map(str::to_string)
                })
                .unwrap_or_default(),
            Ask::Patch => self
                .current_instruction(at)
                .map(|instruction| format_bytes(&instruction.bytes))
                .unwrap_or_default(),
            Ask::ImportLibrary | Ask::ReplaceLibrary | Ask::ExportLibrary => String::new(),
        };
        self.prompt = Some(Prompt {
            ask,
            input,
            at,
            field,
            variable,
        });
    }

    fn current_instruction(&self, displayed: u64) -> Option<&crate::analysis::engine::EngineInsn> {
        self.an
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.insns)
            .find(|instruction| instruction.addr + self.an.display_base == displayed)
    }

    // ── mouse ──

    /// The pane a terminal position belongs to, given the size stored before
    /// the last frame. The layout mirrors `render::draw`, kept in one place so
    /// the two cannot disagree.
    pub fn pane_at(&self, column: u16, row: u16) -> Option<(Focus, usize)> {
        let (w, h) = self.dims;
        if w == 0 || h == 0 {
            return None;
        }
        // header at row 0, footer at h-1; body is rows 1..h-2.
        if row < 1 || row >= h.saturating_sub(1) {
            return None;
        }
        let body_h = h.saturating_sub(2);
        let fns_w = 38.min(w);
        let evidence_h = match self.left {
            LeftView::Sinks if !self.sinks.is_empty() => 6u16.min(body_h),
            LeftView::Types => 7u16.min(body_h),
            _ => 0,
        };
        let xrefs_h = if evidence_h > 0 { 7 } else { 8 }.min(body_h);
        let body_bottom = h.saturating_sub(1);
        let xrefs_start = body_bottom.saturating_sub(xrefs_h);
        let evidence_start = xrefs_start.saturating_sub(evidence_h);
        let left_len = match self.left {
            LeftView::Functions => self.order.len(),
            LeftView::Sinks => self.sinks.len(),
            LeftView::Driver => self.driver_rows().len(),
            LeftView::Types => self.type_rows().len(),
        };
        let (focus, list_len, pane_row) = if column < fns_w {
            (Focus::Functions, left_len, row)
        } else if row >= xrefs_start {
            (
                Focus::Xrefs,
                self.xref_rows().len(),
                row.saturating_sub(xrefs_start),
            )
        } else if evidence_h > 0 && row >= evidence_start {
            // The evidence rail describes the selected attack-surface row. It
            // has no independent cursor; clicking it must not move another pane.
            return None;
        } else {
            (Focus::Listing, self.listing_len(), row)
        };
        // row 0 of the pane is the border, row 1 the title; items start there.
        let mut idx = pane_row.saturating_sub(2) as usize;
        if focus == Focus::Listing && self.graph {
            let inner_width = w.saturating_sub(fns_w).saturating_sub(2);
            let listing_height = evidence_start.saturating_sub(1);
            let inner_height = listing_height.saturating_sub(2);
            let inspector_height = if inner_height >= 9 { 6 } else { 0 };
            let map_height = inner_height.saturating_sub(inspector_height);
            let graph_x = column.saturating_sub(fns_w).saturating_sub(1);
            let graph_y = row.saturating_sub(2);
            idx = self
                .graph_block_at_point(graph_x, graph_y, inner_width, map_height)
                .unwrap_or(self.cursor);
        }
        Some((
            focus,
            if list_len == 0 {
                0
            } else {
                idx.min(list_len - 1)
            },
        ))
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        match m.kind {
            MouseEventKind::ScrollUp => self.step(-1),
            MouseEventKind::ScrollDown => self.step(1),
            MouseEventKind::Down(MouseButton::Left) => {
                let Some((focus, idx)) = self.pane_at(m.column, m.row) else {
                    return;
                };
                self.focus = focus;
                match focus {
                    Focus::Functions => match self.left {
                        LeftView::Sinks => {
                            self.ssel = idx;
                            self.open_sink();
                        }
                        LeftView::Driver => {
                            self.dsel = idx;
                            self.open_driver();
                        }
                        LeftView::Types => {
                            self.tsel = idx;
                            self.open_type();
                        }
                        LeftView::Functions => {
                            self.sel = idx;
                            if let Some(a) = self.selected_addr() {
                                self.open(a, false);
                            }
                        }
                    },
                    Focus::Listing => self.cursor = idx.min(self.listing_len().saturating_sub(1)),
                    Focus::Xrefs => self.xsel = idx,
                }
            }
            _ => {}
        }
    }
}

fn push_type_group(rows: &mut Vec<TyRow>, title: &str, mut group: Vec<TyRow>) {
    if group.is_empty() {
        return;
    }
    rows.push(TyRow {
        label: title.into(),
        detail: String::new(),
        addr: None,
        kind: "section",
        section: true,
    });
    rows.append(&mut group);
}

fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

fn parse_field_ref(text: &str, function: u64, db: &Db) -> Option<FieldRef> {
    let arrow = text.find("->")?;
    let before = &text[..arrow];
    let shown_base: String = before
        .chars()
        .rev()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let base = db
        .variables
        .iter()
        .find_map(|((owner, recovered), alias)| {
            (*owner == function && alias == &shown_base).then_some(recovered.clone())
        })
        .unwrap_or(shown_base);
    if !crate::db::valid_base(&base) {
        return None;
    }
    let member: String = text[arrow + 2..]
        .chars()
        .take_while(|ch| *ch == '_' || ch.is_ascii_alphanumeric())
        .collect();
    let type_name = db.bound_type(function, &base).map(str::to_string);
    let offset = if let Some(hex) = member.strip_prefix("field_m") {
        i64::from_str_radix(hex, 16).ok()?.checked_neg()?
    } else if let Some(hex) = member.strip_prefix("field_") {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        let type_name = type_name.as_ref()?;
        db.fields
            .get(type_name)?
            .iter()
            .find_map(|(&offset, field)| (field.name == member).then_some(offset))?
    };
    Some(FieldRef {
        function,
        base,
        offset,
        type_name,
    })
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    text.match_indices(identifier).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    })
}

fn is_recovered_variable(token: &str) -> bool {
    if token
        .strip_prefix("var_")
        .or_else(|| token.strip_prefix("arg_"))
        .is_some_and(|tail| !tail.is_empty() && tail.chars().all(|ch| ch.is_ascii_hexdigit()))
    {
        return true;
    }
    matches!(
        token,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "al"
            | "bl"
            | "cl"
            | "dl"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
    )
}

fn parse_field_definition(text: &str) -> Result<(String, Option<String>), String> {
    let text = text.trim();
    let (name, data_type) = match text.split_once(':') {
        Some((name, ty)) => (name.trim(), Some(ty.trim())),
        None => (text, None),
    };
    if !crate::db::valid_identifier(name) {
        return Err("field must be NAME or NAME: C_TYPE".into());
    }
    if data_type.is_some_and(|ty| !crate::db::valid_c_type(ty)) {
        return Err("field type must contain C identifiers and pointer stars".into());
    }
    Ok((
        name.to_string(),
        data_type.map(|ty| ty.split_whitespace().collect::<Vec<_>>().join(" ")),
    ))
}

fn parse_prototype(text: &str) -> Result<(String, Vec<String>), String> {
    let text = text.trim();
    let Some((returns, tail)) = text.split_once('(') else {
        return Err("use RETURN (PARAM, PARAM), for example bool (void *, size_t)".into());
    };
    let Some(parameters) = tail.strip_suffix(')') else {
        return Err("prototype must end with ')'".into());
    };
    if parameters.contains('(') || parameters.contains(')') {
        return Err("nested function types are not supported".into());
    }
    let returns = returns.trim();
    if returns.is_empty() {
        return Err("prototype needs a return type".into());
    }
    let parameters = parameters.trim();
    let params = if parameters.is_empty() || parameters == "void" {
        Vec::new()
    } else {
        let params: Vec<String> = parameters
            .split(',')
            .map(str::trim)
            .map(str::to_string)
            .collect();
        if params.iter().any(String::is_empty) {
            return Err("each comma-separated parameter needs a type".into());
        }
        params
    };
    Ok((returns.to_string(), params))
}

/// Run the interactive view until the user quits.
///
/// The analysis runs on a worker thread while the splash plays, so opening a
/// large binary shows the animation immediately instead of a frozen terminal;
/// `q` / Esc / Ctrl-C quit even while it is still working.
pub fn run(bin: Binary, bytes: Vec<u8>, db: Db, title: String) -> Result<()> {
    // The worker recovers the functions, ranks the sinks, and builds the
    // literal map. The main thread only renders, so the splash animates for
    // exactly as long as the analysis takes, then the app takes over with the
    // ready result.
    let (tx, rx) = std::sync::mpsc::channel::<WorkResult>();
    let (b, by, d) = (bin.clone(), bytes.clone(), db.clone());
    std::thread::spawn(move || {
        let an = engine::analyze(&b, &by, crate::ANALYSIS_BUDGET, &d);
        let mut sinks = crate::analysis::audit::run(&an, &b, &by);
        sinks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.reachable.cmp(&a.reachable))
                .then(a.addr.cmp(&b.addr))
        });
        let strings = listing::string_map(&b, &by, engine::display_base(&b));
        let _ = tx.send((an, sinks, strings));
    });

    // `try_init` rather than `init`, so running this with output piped fails
    // with a sentence instead of a panic. It installs a panic hook that
    // restores the terminal, so a crash cannot leave the shell in raw mode.
    let mut term = ratatui::try_init()
        .map_err(|e| anyhow::anyhow!("cannot start the interactive view: {e}"))?;
    let _ = ratatui::crossterm::execute!(&mut stdout(), event::EnableMouseCapture);

    // Phase 1: animate while the analysis runs. `Ok(None)` is a quit request.
    let mut frame: u64 = 0;
    let ready: Result<Option<WorkResult>> = 'work: loop {
        frame = frame.saturating_add(1);
        if let Err(e) = term.draw(|f| splash::draw(f, f.area(), frame, true)) {
            break 'work Err(e.into());
        }
        match rx.try_recv() {
            Ok(ready) => break 'work Ok(Some(ready)),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                break 'work Err(anyhow::anyhow!("the analysis worker died"));
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        match event::poll(Duration::from_millis(33)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) => {
                    let quit = k.kind == KeyEventKind::Press
                        && (matches!(k.code, KeyCode::Char('q') | KeyCode::Esc)
                            || (k.code == KeyCode::Char('c')
                                && k.modifiers.contains(KeyModifiers::CONTROL)));
                    if quit {
                        break 'work Ok(None);
                    }
                }
                Ok(Event::Mouse(_)) | Ok(_) => {}
                Err(e) => break 'work Err(e.into()),
            },
            Ok(false) => {}
            Err(e) => break 'work Err(e.into()),
        }
    };

    let (an, sinks, strings) = match ready {
        Ok(Some(ready)) => ready,
        Ok(None) => {
            let _ = ratatui::crossterm::execute!(&mut stdout(), event::DisableMouseCapture);
            ratatui::restore();
            return Ok(());
        }
        Err(e) => {
            let _ = ratatui::crossterm::execute!(&mut stdout(), event::DisableMouseCapture);
            ratatui::restore();
            return Err(e);
        }
    };
    if an.functions.is_empty() {
        let _ = ratatui::crossterm::execute!(&mut stdout(), event::DisableMouseCapture);
        ratatui::restore();
        anyhow::bail!("no functions were recovered, so there is nothing to browse");
    }

    // The heavy work is done; the splash replays from the top and any key skips
    // the rest of it. The tick stays fast while the splash plays and relaxes
    // once it is gone: an idle TUI at 30fps only burns CPU for the spinner.
    let driver = if crate::analysis::driver::plausibly_a_driver(&bin) {
        Some(crate::analysis::driver::report(&bin, &bytes, &an, &strings))
    } else {
        None
    };
    let mut app = App::new(bin, bytes, db, an, sinks, strings, driver, title);
    let res = loop {
        app.frame = app.frame.saturating_add(1);
        if app.splash && app.frame > splash::SPLASH_FRAMES {
            app.splash = false;
        }
        if let Ok(area) = term.size() {
            app.dims = (area.width, area.height);
        }
        if let Err(e) = term.draw(|f| render::draw(f, &app)) {
            break Err(e.into());
        }
        // Poll with a short timeout instead of blocking on read: a tick with no
        // input redraws, which is what makes the splash and the header spinner
        // move without keys.
        let tick = if app.splash {
            Duration::from_millis(33)
        } else {
            Duration::from_millis(150)
        };
        match event::poll(tick) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) => app.on_key(k),
                Ok(Event::Mouse(m)) => app.on_mouse(m),
                Ok(_) => {}
                Err(e) => break Err(e.into()),
            },
            Ok(false) => {}
            Err(e) => break Err(e.into()),
        }
        if app.quit {
            break Ok(());
        }
    };
    let _ = ratatui::crossterm::execute!(&mut stdout(), event::DisableMouseCapture);
    ratatui::restore();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Arch, Format, Section};

    fn app_with(code: &[u8], vaddr: u64) -> App {
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = vaddr;
        bin.sections = vec![Section {
            name: ".text".into(),
            vaddr,
            vsize: code.len() as u64,
            file_off: vaddr,
            file_size: code.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: true,
        }];
        let mut bytes = vec![0u8; vaddr as usize];
        bytes.extend_from_slice(code);
        let db = Db::default();
        let an = engine::analyze(&bin, &bytes, 10_000, &db);
        let sinks = ranked_sinks(&an, &bin, &bytes);
        let strings = listing::string_map(&bin, &bytes, engine::display_base(&bin));
        App::new(bin, bytes, db, an, sinks, strings, None, "t".into())
    }

    /// The audit, ranked the same way the interactive session ranks it.
    fn ranked_sinks(
        an: &crate::analysis::engine::Analysis,
        bin: &Binary,
        bytes: &[u8],
    ) -> Vec<crate::analysis::audit::Finding> {
        let mut sinks = crate::analysis::audit::run(an, bin, bytes);
        sinks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.reachable.cmp(&a.reachable))
                .then(a.addr.cmp(&b.addr))
        });
        sinks
    }

    /// entry calls sub, both return.
    fn two_functions() -> App {
        // 0x1000: e8 06 00 00 00   call 0x100b
        // 0x1005: c3               ret
        // ...pad...
        // 0x100b: c3               ret
        let mut code = vec![0u8; 12];
        code[0] = 0xe8;
        code[1..5].copy_from_slice(&6i32.to_le_bytes());
        code[5] = 0xc3;
        code[11] = 0xc3;
        app_with(&code, 0x1000)
    }

    #[test]
    fn assembly_patch_stages_reanalyzes_and_restores_original_bytes() {
        // mov eax, 1; ret -> xor eax, eax; nop; nop; nop; ret
        let original = [0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3];
        let mut app = app_with(&original, 0x1000);
        app.focus = Focus::Listing;
        app.open(0x1000, false);
        app.cursor = app
            .lines
            .iter()
            .position(|line| matches!(line, Line::Insn { addr: 0x1000, .. }))
            .expect("entry instruction");

        app.ask(Ask::Patch);
        let prompt = app.prompt.take().expect("patch prompt");
        assert_eq!(prompt.at, 0x1000);
        assert_eq!(prompt.input, "b8 01 00 00 00");

        app.commit(Ask::Patch, 0x1000, "31 c0 90 90 90".into());
        assert_eq!(&app.bytes[0x1000..0x1005], &[0x31, 0xc0, 0x90, 0x90, 0x90]);
        assert_eq!(app.db.patches.len(), 5);
        assert!(app.lines.iter().any(|line| matches!(
            line,
            Line::Insn { addr: 0x1000, mnemonic, .. } if mnemonic == "xor"
        )));
        assert!(app.status.contains("staged 5 bytes"));

        app.commit(Ask::Patch, 0x1000, String::new());
        assert_eq!(&app.bytes[0x1000..0x1006], &original);
        assert!(app.db.patches.is_empty());
        assert!(app.lines.iter().any(|line| matches!(
            line,
            Line::Insn { addr: 0x1000, mnemonic, .. } if mnemonic == "mov"
        )));
        assert!(app.status.contains("restored 5 staged bytes"));
    }

    #[test]
    fn opens_something_on_start() {
        let app = two_functions();
        assert!(app.cur.is_some(), "a pane should never start empty");
        assert!(!app.lines.is_empty());
    }

    #[test]
    fn filtering_keeps_the_selection_when_it_survives() {
        let mut app = two_functions();
        let before = app.selected_addr();
        app.filter = "entry".into();
        app.refilter();
        assert_eq!(app.selected_addr(), before);
        assert_eq!(app.order.len(), 1);
    }

    #[test]
    fn filtering_that_matches_nothing_leaves_an_empty_list() {
        let mut app = two_functions();
        app.filter = "nothing_matches_this".into();
        app.refilter();
        assert!(app.order.is_empty());
        assert_eq!(app.selected_addr(), None);
        // and navigation on an empty list must not panic
        app.move_sel(1);
        app.move_sel(-1);
    }

    #[test]
    fn following_a_call_pushes_history_and_back_returns() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        // the call is the first instruction
        app.cursor = 0;
        app.follow();
        assert_eq!(app.cur, Some(0x100b), "followed into the callee");

        app.back();
        assert_eq!(app.cur, Some(0x1000), "and came back");
        assert!(app.history.is_empty());
    }

    #[test]
    fn toggling_pseudocode_shows_decompiled_lines_and_back_to_asm() {
        let mut app = two_functions();
        app.open(0x1000, false);
        let asm = app.lines.len();
        assert!(!app.pseudo);

        app.toggle_pseudo();
        assert!(app.pseudo, "the pseudocode view is on");
        assert!(!app.pseudo_lines.is_empty(), "and it has decompiled lines");
        assert_eq!(app.cursor, 0, "the cursor resets to the top");
        // Navigation now clamps to the pseudocode, not the disassembly.
        app.focus = Focus::Listing;
        app.move_cursor(10_000);
        assert!(app.cursor < app.pseudo_lines.len());

        app.toggle_pseudo();
        assert!(!app.pseudo, "toggles back to disassembly");
        assert_eq!(app.lines.len(), asm, "and the disassembly is intact");
    }

    #[test]
    fn pseudocode_type_and_field_names_persist_and_refresh_in_place() {
        // mov eax,[rcx+8]; ret
        let mut app = app_with(&[0x8b, 0x41, 0x08, 0xc3], 0x1000);
        app.splash = false;
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_pseudo();
        app.cursor = app
            .pseudo_lines
            .iter()
            .position(|line| line.text.contains("field_8"))
            .expect("synthetic field");

        let field = app.selected_field_ref().expect("selected field context");
        assert_eq!(field.base, "rcx");
        assert_eq!(field.offset, 8);
        app.commit_with_context(Ask::Type, 0x1000, "CONTEXT".into(), Some(field), None);
        assert_eq!(app.db.bound_type(0x1000, "rcx"), Some("CONTEXT"));
        assert!(app.pseudo_lines[0].text.contains("CONTEXT * rcx"));

        app.cursor = app
            .pseudo_lines
            .iter()
            .position(|line| line.text.contains("field_8"))
            .expect("field remains synthetic until named");
        let field = app.selected_field_ref().expect("bound field context");
        app.commit_with_context(Ask::Field, 0x1000, "length".into(), Some(field), None);
        assert_eq!(app.db.field_name(0x1000, "rcx", 8), Some("length"));
        assert!(app
            .pseudo_lines
            .iter()
            .any(|line| line.text.contains("rcx->length")));
    }

    #[test]
    fn pseudocode_variable_aliases_refresh_and_keep_stable_field_identity() {
        let mut app = app_with(&[0x8b, 0x41, 0x08, 0xc3], 0x1000);
        app.splash = false;
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_pseudo();
        app.cursor = app
            .pseudo_lines
            .iter()
            .position(|line| line.text.contains("rcx->field_8"))
            .expect("field line");

        let variable = app.selected_variable_ref().expect("variable context");
        assert_eq!(variable.base, "rcx");
        app.commit_with_context(
            Ask::Variable,
            0x1000,
            "request".into(),
            None,
            Some(variable),
        );
        assert_eq!(app.db.variable_name(0x1000, "rcx"), Some("request"));
        assert!(app
            .pseudo_lines
            .iter()
            .any(|line| line.text.contains("request->field_8")));

        app.cursor = app
            .pseudo_lines
            .iter()
            .position(|line| line.text.contains("request->field_8"))
            .unwrap();
        assert_eq!(app.selected_field_ref().unwrap().base, "rcx");
        app.ask(Ask::Variable);
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.input.as_str()),
            Some("request")
        );
        app.prompt = None;
        app.commit_with_context(
            Ask::Variable,
            0x1000,
            String::new(),
            None,
            Some(VariableRef {
                function: 0x1000,
                base: "rcx".into(),
            }),
        );
        assert!(app.db.variable_name(0x1000, "rcx").is_none());
        assert!(app
            .pseudo_lines
            .iter()
            .any(|line| line.text.contains("rcx->field_8")));
    }

    #[test]
    fn pseudocode_prototype_persists_refreshes_and_clears_in_place() {
        let mut app = app_with(&[0x48, 0x8b, 0xc1, 0xc3], 0x1000);
        app.splash = false;
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_pseudo();

        app.commit_with_context(
            Ask::Prototype,
            0x1000,
            "bool (CONTEXT *, size_t)".into(),
            None,
            None,
        );
        let prototype = app.db.prototype(0x1000).expect("stored prototype");
        assert_eq!(prototype.returns, "bool");
        assert_eq!(prototype.params, ["CONTEXT *", "size_t"]);
        assert_eq!(
            app.pseudo_lines[0].text,
            "bool entry(CONTEXT * rdi, size_t rsi) {"
        );

        app.ask(Ask::Prototype);
        assert_eq!(
            app.prompt.as_ref().map(|prompt| prompt.input.as_str()),
            Some("bool (CONTEXT *, size_t)")
        );
        app.prompt = None;
        app.commit_with_context(Ask::Prototype, 0x1000, String::new(), None, None);
        assert!(app.db.prototype(0x1000).is_none());
        assert!(app.pseudo_lines[0].text.starts_with("uintptr_t entry("));
    }

    #[test]
    fn field_prompt_parser_accepts_optional_c_types() {
        assert_eq!(
            parse_field_definition("IoStatus: NTSTATUS").unwrap(),
            ("IoStatus".into(), Some("NTSTATUS".into()))
        );
        assert_eq!(
            parse_field_definition("buffer: const uint8_t *").unwrap(),
            ("buffer".into(), Some("const uint8_t *".into()))
        );
        assert_eq!(
            parse_field_definition("length").unwrap(),
            ("length".into(), None)
        );
        assert!(parse_field_definition("bad-name: u32").is_err());
        assert!(parse_field_definition("flags: bad-type").is_err());
    }

    #[test]
    fn prototype_prompt_parser_is_strict_but_accepts_void() {
        assert_eq!(
            parse_prototype("bool (CONTEXT *, size_t)").unwrap(),
            ("bool".into(), vec!["CONTEXT *".into(), "size_t".into()])
        );
        assert_eq!(
            parse_prototype("void (void)").unwrap().1,
            Vec::<String>::new()
        );
        assert!(parse_prototype("bool CONTEXT *").is_err());
        assert!(parse_prototype("bool (size_t,)").is_err());
    }

    #[test]
    fn function_graph_renders_and_enter_opens_the_selected_block() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_graph();
        assert!(app.graph, "the function graph is on");
        assert!(!app.pseudo, "graph and pseudocode are mutually exclusive");
        assert_eq!(app.cursor_addr(), Some(0x1000));

        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("function graph"), "the graph title is visible");
        assert!(out.contains("B00"), "basic blocks have stable card ids");
        assert!(out.contains("RETURN"), "terminal flow is classified");

        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(!app.graph, "enter returns to the assembly listing");
        assert_eq!(app.cursor_addr(), Some(0x1000));
    }

    fn conditional_graph() -> App {
        // xor eax,eax; je 0x1006; two return arms.
        let mut app = app_with(&[0x31, 0xc0, 0x74, 0x02, 0x90, 0xc3, 0xc3], 0x1000);
        app.splash = false;
        app
    }

    #[test]
    fn function_graph_labels_both_sides_of_a_conditional_branch() {
        // 0x1000: xor eax, eax
        // 0x1002: je  0x1006
        // 0x1004: nop
        // 0x1005: ret
        // 0x1006: ret
        let mut app = conditional_graph();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_graph();

        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("TRUE"), "the taken edge is labelled");
        assert!(out.contains("FALSE"), "the fall-through edge is labelled");
        assert!(
            out.contains("B01") && out.contains("B02"),
            "all branch blocks render"
        );
    }

    #[test]
    fn graph_navigation_follows_layers_and_sibling_lanes() {
        let mut app = conditional_graph();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_graph();

        let narrow = graph_layout(app.current_function().unwrap(), 10);
        assert!(
            narrow.width >= 18,
            "sibling nodes get a scrollable logical canvas"
        );
        assert_ne!(
            narrow.nodes[1].x, narrow.nodes[2].x,
            "narrow views do not overlap branches"
        );

        app.on_key(KeyEvent::from(KeyCode::Down));
        assert_eq!(
            app.cursor, 2,
            "down selects the nearest block in the next layer"
        );
        app.on_key(KeyEvent::from(KeyCode::Left));
        assert_eq!(app.cursor, 1, "left moves to the sibling lane");
        app.on_key(KeyEvent::from(KeyCode::Up));
        assert_eq!(app.cursor, 0, "up returns to the entry layer");
    }

    #[test]
    fn function_graph_marks_loop_back_edges() {
        // xor ecx,ecx; inc ecx; cmp ecx,3; jne 0x1002; ret
        let mut app = app_with(
            &[0x31, 0xc9, 0xff, 0xc1, 0x83, 0xf9, 0x03, 0x75, 0xf9, 0xc3],
            0x1000,
        );
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_graph();
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains('↑'), "loop back edges should stay visible");
    }

    #[test]
    fn clicking_a_spatial_graph_node_selects_that_block() {
        let mut app = conditional_graph();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_graph();
        app.dims = (110, 30);
        // At this size B02 is the right-hand node in layer one.
        app.on_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 84, 5));
        assert_eq!(app.cursor, 2);
    }

    #[test]
    fn searching_the_listing_moves_the_cursor_to_a_match() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.cursor = 0;
        app.search_listing("ret".into());
        assert!(
            app.line_text(app.cursor).to_lowercase().contains("ret"),
            "the cursor should land on a line containing the query"
        );
        assert!(app.status.contains("match"));

        app.search_listing("no_such_text_here".into());
        assert!(app.status.contains("no match"));
    }

    #[test]
    fn the_left_pane_cycles_functions_sinks_driver_and_types() {
        let mut app = two_functions();
        assert_eq!(app.left, LeftView::Functions);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Sinks);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Driver);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Types);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Functions);
        // With no sinks recovered, navigating them must not panic.
        app.left = LeftView::Sinks;
        app.move_ssel(1);
        app.move_ssel(-1);
        // Driver view is read-only: stepping must not move anything.
        app.left = LeftView::Driver;
        app.step(1);
        app.step(-1);
        app.left = LeftView::Types;
        app.step(1);
        app.step(-1);
        app.open_sink();
        assert_eq!(app.ssel, 0);
    }

    #[test]
    fn the_type_browser_groups_filters_and_opens_analyst_facts() {
        let mut app = two_functions();
        app.db.set_field("CONTEXT", 8, "length").unwrap();
        app.db.bind_type(0x1000, "rdi", "CONTEXT").unwrap();
        app.db.set_variable(0x1000, "rdi", "context").unwrap();
        app.db
            .set_prototype(0x100b, "bool", &["CONTEXT *".into()])
            .unwrap();
        app.left = LeftView::Types;
        app.move_tsel(1);

        let rows = app.type_rows();
        assert!(rows.iter().any(|row| row.label == "PROTOTYPES"));
        assert!(rows.iter().any(|row| row.label == "STRUCTURES"));
        assert!(rows.iter().any(|row| row.label == "BINDINGS"));
        assert!(rows.iter().any(|row| row.label == "VARIABLES"));
        assert!(rows.iter().any(|row| {
            row.kind == "layout" && row.label == "CONTEXT" && row.detail.contains("length")
        }));
        assert!(rows.iter().any(|row| {
            row.kind == "variable" && row.label.ends_with(":rdi") && row.detail == "context"
        }));

        app.tysrch = "sub_100b".into();
        app.clamp_tsel();
        let filtered = app.type_rows();
        let prototype_index = filtered
            .iter()
            .position(|row| row.kind == "prototype")
            .expect("filtered prototype row");
        app.tsel = prototype_index;
        app.open_type();
        assert_eq!(app.cur, Some(0x100b));
        assert_eq!(app.focus, Focus::Listing);

        app.left = LeftView::Types;
        let out = rendered(&mut app, 120, 32);
        assert!(out.contains("types /sub_100b"));
        assert!(out.contains("type fact"));
        assert!(out.contains("PROTOTYPE"));
    }

    #[test]
    fn type_library_controls_round_trip_typed_layouts_in_place() {
        let mut path = std::env::temp_dir();
        path.push(format!("knife-tui-typelib-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut app = two_functions();
        app.splash = false;
        app.db
            .set_typed_field("CONTEXT", 8, "length", Some("size_t"))
            .unwrap();
        app.commit(Ask::ExportLibrary, 0, path.to_string_lossy().into_owned());
        assert!(app.status.contains("exported 1 type / 1 field"));

        app.db.clear_field("CONTEXT", 8);
        assert!(app.db.fields.is_empty());
        app.commit(Ask::ImportLibrary, 0, path.to_string_lossy().into_owned());
        assert_eq!(app.db.fields["CONTEXT"][&8].name, "length");
        assert_eq!(
            app.db.fields["CONTEXT"][&8].data_type.as_deref(),
            Some("size_t")
        );
        assert!(app.status.contains("imported 1 type / 1 field"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn type_library_shortcuts_are_scoped_to_the_types_pane() {
        let mut app = two_functions();
        app.splash = false;
        app.focus = Focus::Functions;
        app.left = LeftView::Functions;
        app.on_key(KeyEvent::from(KeyCode::Char('I')));
        assert!(app.prompt.is_none());

        app.left = LeftView::Types;
        for (key, expected) in [
            ('I', Ask::ImportLibrary),
            ('R', Ask::ReplaceLibrary),
            ('E', Ask::ExportLibrary),
        ] {
            app.on_key(KeyEvent::from(KeyCode::Char(key)));
            assert_eq!(app.prompt.as_ref().map(|prompt| prompt.ask), Some(expected));
            app.prompt = None;
        }
    }

    /// An `App` over the synthetic driver fixture, ready to show the driver pane.
    fn driver_app() -> App {
        let buf = crate::formats::fixture::pe_with_driver();
        let bin = crate::formats::analyze("fixture.sys", &buf).unwrap();
        let db = Db::default();
        let an = engine::analyze(&bin, &buf, 100_000, &db);
        let sinks = ranked_sinks(&an, &bin, &buf);
        let strings = listing::string_map(&bin, &buf, engine::display_base(&bin));
        let drv = crate::analysis::driver::report(&bin, &buf, &an, &strings);
        App::new(bin, buf, db, an, sinks, strings, Some(drv), "t".into())
    }

    #[test]
    fn the_driver_view_renders_the_report() {
        let mut app = driver_app();
        app.left = LeftView::Driver;
        let out = rendered(&mut app, 120, 40);
        assert!(
            out.contains("Knifelab"),
            "device name shows in the driver pane:\n{out}"
        );
        assert!(out.to_lowercase().contains("driver"));
        assert!(out.contains("IRP_MJ_DEVICE_CONTROL") || out.contains("ioctls"));
    }

    #[test]
    fn the_driver_pane_jumps_to_a_primitive_site() {
        let mut app = driver_app();
        app.left = LeftView::Driver;
        let idx = app
            .driver_rows()
            .iter()
            .enumerate()
            .find(|(_, r)| !r.section && r.label.starts_with("MmMapIoSpace"))
            .map(|(i, _)| i)
            .expect("a MmMapIoSpace site row");
        app.dsel = idx;
        let expected = app.driver_rows()[idx]
            .addr
            .expect("site row has an address");
        app.open_driver();
        assert_eq!(app.focus, Focus::Listing);
        // The listing opens the containing function and lands on the site line.
        assert_eq!(
            app.cur,
            Some(0x1100),
            "the site sits inside DispatchDeviceControl"
        );
        assert!(
            app.lines.iter().any(|l| l.addr() == expected),
            "the primitive call site appears in the listing"
        );
    }

    #[test]
    fn the_driver_pane_filters_primitives() {
        let mut app = driver_app();
        app.left = LeftView::Driver;
        let all = app.driver_rows().len();

        // Reachable-only hides the orphaned KeInitializeMutex helper.
        app.dreach = true;
        let reach = app.driver_rows();
        assert!(reach.len() < all, "reachable-only shrinks the pane");
        assert!(!reach
            .iter()
            .any(|r| r.label.starts_with("KeInitializeMutex")));

        // Severity gate >= 3 drops sev1/sev2 primitive rows.
        app.dreach = false;
        app.dminsev = 3;
        let severe = app.driver_rows();
        assert!(severe
            .iter()
            .filter(|r| !r.section)
            .all(|r| { !r.detail.starts_with("sev1") && !r.detail.starts_with("sev2") }));
        assert!(severe.iter().any(|r| r.label.starts_with("MmMapIoSpace")));
    }

    #[test]
    fn the_driver_pane_names_the_selected_row() {
        let mut app = driver_app();
        app.left = LeftView::Driver;
        let rows = app.driver_rows();
        let idx = rows
            .iter()
            .enumerate()
            .find(|(_, r)| !r.section)
            .map(|(i, _)| i)
            .expect("at least one navigable row");
        app.dsel = idx;
        assert_eq!(app.cursor_addr(), rows[idx].addr);
    }

    #[test]
    fn the_reference_pane_toggles_callers_and_callees() {
        let mut app = two_functions();
        app.focus = Focus::Listing;
        // Callees of entry: it calls sub_100b.
        app.open(0x1000, false);
        app.refview = RefView::From;
        let rows = app.xref_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].jump, 0x100b);
        // Callers of sub_100b: entry, from 0x1000.
        app.open(0x100b, false);
        app.refview = RefView::To;
        let rows = app.xref_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].jump, 0x1000);
        // Toggling flips the view and resets the selection.
        app.xsel = 5;
        app.toggle_refs();
        assert_eq!(app.refview, RefView::From);
        assert_eq!(app.xsel, 0);
    }

    #[test]
    fn following_in_the_pseudocode_view_asks_to_switch() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.toggle_pseudo();
        app.focus = Focus::Listing;
        app.follow();
        assert!(app.status.contains("disassembly"));
        assert!(
            app.pseudo,
            "following did not navigate away from pseudocode"
        );
    }

    #[test]
    fn changing_function_in_pseudo_mode_recomputes_it() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.toggle_pseudo();
        let first = app.pseudo_lines.clone();
        app.open(0x100b, false); // the callee
        assert!(app.pseudo, "still in pseudocode mode");
        assert!(!app.pseudo_lines.is_empty());
        // A different function decompiles to different text.
        assert_ne!(
            first.iter().map(|l| &l.text).collect::<Vec<_>>(),
            app.pseudo_lines.iter().map(|l| &l.text).collect::<Vec<_>>()
        );
    }

    #[test]
    fn back_with_no_history_says_so_instead_of_panicking() {
        let mut app = two_functions();
        app.history.clear();
        app.back();
        assert!(app.status.contains("nothing to go back to"));
    }

    #[test]
    fn naming_updates_the_list_and_the_database() {
        let mut app = two_functions();
        app.open(0x100b, false);
        app.commit(Ask::Name, 0x100b, "parse_header".into());

        assert_eq!(app.an.label(0x100b), "parse_header");
        assert_eq!(
            app.db.names.get(&0x100b).map(String::as_str),
            Some("parse_header")
        );
        assert!(app
            .order
            .iter()
            .any(|&i| app.an.functions[i].name == "parse_header"));
    }

    #[test]
    fn an_empty_name_clears_it() {
        let mut app = two_functions();
        app.commit(Ask::Name, 0x100b, "tmp".into());
        assert_eq!(app.an.label(0x100b), "tmp");
        app.commit(Ask::Name, 0x100b, String::new());
        assert_eq!(app.an.label(0x100b), "sub_100b");
        assert!(app.db.names.is_empty());
    }

    #[test]
    fn a_note_shows_up_in_the_listing() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.commit(Ask::Note, 0x1000, "starts here".into());
        let annotated = app.lines.iter().any(|l| {
            matches!(l, Line::Insn { annot: Some(crate::listing::Annot::Note(n)), .. } if n == "starts here")
        });
        assert!(annotated, "the note should appear against the instruction");
    }

    #[test]
    fn goto_accepts_a_symbol_or_an_address() {
        let mut app = two_functions();
        app.commit(Ask::Goto, 0, "0x100b".into());
        assert_eq!(app.cur, Some(0x100b));

        app.commit(Ask::Goto, 0, "entry".into());
        assert_eq!(app.cur, Some(0x1000));

        app.commit(Ask::Goto, 0, "no_such_thing".into());
        assert!(app.status.contains("no symbol or address"));
    }

    #[test]
    fn opening_an_address_inside_a_function_lands_on_that_line() {
        let mut app = two_functions();
        app.open(0x1005, false); // the `ret`, not the function head
        assert_eq!(app.cur, Some(0x1000), "resolves to the containing function");
        assert_eq!(
            app.lines.get(app.cursor).map(Line::addr),
            Some(0x1005),
            "and puts the cursor on the requested address"
        );
    }

    /// Draw the whole interface into an off-screen buffer and return its text.
    /// This is the only automated check that rendering does not panic, which
    /// matters because a layout mistake shows up as a crash, not a wrong pixel.
    /// The splash is turned off so these tests exercise the main view.
    fn rendered(app: &mut App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        app.splash = false;
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| render::draw(f, app)).unwrap();
        term.backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }

    #[test]
    fn the_interface_renders() {
        let mut app = two_functions();
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("functions"), "the function list is drawn");
        assert!(out.contains("entry"), "and lists what was recovered");
        assert!(out.contains("xrefs"), "the xref pane is drawn");
        assert!(out.contains("open/follow"), "the key hints are drawn");
    }

    #[test]
    fn the_sinks_pane_renders() {
        let mut app = two_functions();
        app.sinks.push(crate::analysis::audit::Finding {
            addr: 0x1004,
            func: Some("parse_packet".into()),
            api: "printf".into(),
            pattern: "format-string",
            severity: 3,
            detail: "format argument originates from an external-input API, not a constant string"
                .into(),
            reachable: true,
        });
        app.toggle_sinks();
        let out = rendered(&mut app, 110, 30);
        assert!(
            out.contains("attack surface"),
            "the attack-surface pane is drawn"
        );
        assert!(out.contains("evidence"), "the evidence rail is drawn");
        assert!(out.contains("HIGH"), "severity is visible");
        assert!(
            out.contains("EXTERNAL INPUT"),
            "the provenance signal is visible"
        );
    }

    #[test]
    fn the_pseudocode_view_renders() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.toggle_pseudo();
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("pseudocode"), "the pseudocode pane is drawn");
        assert!(out.contains("sub_"), "and shows a decompiled signature");
    }

    #[test]
    fn it_renders_in_a_very_small_terminal() {
        // Layout arithmetic that underflows shows up here as a panic.
        let mut app = two_functions();
        for (w, h) in [(20u16, 6u16), (40, 10), (1, 1), (200, 60)] {
            let _ = rendered(&mut app, w, h);
        }
    }

    #[test]
    fn the_help_overlay_and_prompt_render() {
        let mut app = two_functions();
        app.help = true;
        assert!(rendered(&mut app, 110, 30).contains("re-analyse"));

        app.help = false;
        app.prompt = Some(Prompt {
            ask: Ask::Name,
            input: "parse_header".into(),
            at: 0x1000,
            field: None,
            variable: None,
        });
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("name:"), "the prompt shows what it wants");
        assert!(out.contains("parse_header"), "and what has been typed");
    }

    #[test]
    fn typing_in_a_prompt_edits_it_and_escape_abandons_it() {
        let mut app = two_functions();
        app.splash = false;
        app.on_key(KeyEvent::from(KeyCode::Char('n')));
        assert!(app.prompt.is_some());

        for c in "abc".chars() {
            app.on_key(KeyEvent::from(KeyCode::Char(c)));
        }
        app.on_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(app.prompt.as_ref().unwrap().input, "ab");

        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.prompt.is_none(), "escape abandons without saving");
        assert!(app.db.names.is_empty());
        assert!(!app.quit, "escape closed the prompt, it did not quit");
    }

    #[test]
    fn key_releases_are_ignored() {
        // Windows delivers press and release; acting on both moves twice.
        let mut app = two_functions();
        app.focus = Focus::Functions;
        let before = app.sel;
        app.on_key(KeyEvent::new_with_kind(
            KeyCode::Down,
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ));
        assert_eq!(app.sel, before);
    }

    // ── xrefs pane ──

    #[test]
    fn tab_cycles_through_three_panes() {
        let mut app = two_functions();
        app.splash = false;
        assert_eq!(app.focus, Focus::Functions);
        for _ in 0..2 {
            app.on_key(KeyEvent::from(KeyCode::Tab));
        }
        assert_eq!(app.focus, Focus::Xrefs);
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Functions);
    }

    #[test]
    fn the_xref_cursor_jumps_to_the_reference_site() {
        let mut app = two_functions();
        app.splash = false;
        // sub_100b is called once, from 0x1000.
        app.open(0x100b, false);
        assert_eq!(app.xref_rows().len(), 1);
        app.focus = Focus::Xrefs;
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.cur, Some(0x1000), "jumped to the call site");
        assert_eq!(app.focus, Focus::Listing, "and landed in the listing");
    }

    #[test]
    fn xsel_is_clamped_when_the_target_changes() {
        let mut app = two_functions();
        app.open(0x100b, false); // one reference
        app.focus = Focus::Xrefs;
        app.xsel = 5;
        app.open(0x1000, false); // entry has no references
        assert_eq!(app.xsel, 0);
    }

    #[test]
    fn nothing_to_jump_to_says_so_instead_of_panicking() {
        let mut app = two_functions();
        app.splash = false;
        app.open(0x1000, false); // entry has no incoming references
        app.focus = Focus::Xrefs;
        app.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.status.contains("no reference"));
    }

    // ── data refs ──

    /// entry lea's the string and returns; the literal sits in .rodata.
    fn data_ref_app() -> App {
        // lea rax, [rip+0x15] at 0x1000: ends at 0x1007, targets 0x101c.
        let mut bytes = vec![0x48, 0x8d, 0x05, 0x15, 0x00, 0x00, 0x00, 0xc3];
        bytes.extend_from_slice(b"hi there");
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = 0x1000;
        bin.sections = vec![
            Section {
                name: ".text".into(),
                vaddr: 0x1000,
                vsize: 8,
                file_off: 0,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: true,
            },
            Section {
                name: ".rodata".into(),
                vaddr: 0x101c,
                vsize: 8,
                file_off: 8,
                file_size: 8,
                entropy: 0.0,
                read: true,
                write: false,
                exec: false,
            },
        ];
        let db = Db::default();
        let an = engine::analyze(&bin, &bytes, 10_000, &db);
        let sinks = ranked_sinks(&an, &bin, &bytes);
        let strings = listing::string_map(&bin, &bytes, engine::display_base(&bin));
        App::new(bin, bytes, db, an, sinks, strings, None, "t".into())
    }

    #[test]
    fn the_literal_is_annotated_in_the_listing() {
        let app = data_ref_app();
        assert!(
            app.lines.iter().any(|l| matches!(
                l,
                Line::Insn {
                    annot: Some(crate::listing::Annot::Text(t)),
                    ..
                } if t == "hi there"
            )),
            "the lea should be annotated with the literal"
        );
    }

    #[test]
    fn following_a_string_operand_opens_its_bytes() {
        let mut app = data_ref_app();
        app.focus = Focus::Listing;
        app.cursor = 0; // the lea
        app.follow();
        assert_eq!(app.cur, Some(0x101c), "followed the data ref");
        assert!(
            app.lines.iter().all(|l| matches!(l, Line::Data { .. })),
            "a string opens as a hex dump, not as code"
        );

        app.back();
        assert_eq!(app.cur, Some(0x1000), "and back returns to the lea");
        assert_eq!(app.cursor, 0);
    }

    // ── mouse ──

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn the_wheel_scrolls_the_focused_pane() {
        let mut app = data_ref_app();
        app.focus = Focus::Listing;
        app.cursor = 0;
        app.on_mouse(mouse(MouseEventKind::ScrollDown, 0, 0));
        assert_eq!(app.cursor, 1, "wheel scrolls the listing");

        app.focus = Focus::Functions;
        let before = app.sel;
        app.on_mouse(mouse(MouseEventKind::ScrollUp, 0, 0));
        assert_eq!(app.sel, before.saturating_sub(1), "and the function list");
    }

    #[test]
    fn a_click_focuses_that_pane_and_selects_the_row() {
        let mut app = data_ref_app();
        app.dims = (110, 30);
        // A click in the left pane lands on the function list; with a single
        // recovered function the row index clamps to it.
        app.on_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 5, 4));
        assert_eq!(app.focus, Focus::Functions);
        assert_eq!(app.selected_addr(), Some(0x1000));

        // A click in the bottom-right corner lands in the xrefs pane.
        app.on_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 60, 26));
        assert_eq!(app.focus, Focus::Xrefs);
    }

    // ── splash ──

    #[test]
    fn the_splash_renders_animated_knife_art() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = two_functions();
        app.splash = true;
        // Drawn directly rather than through `rendered`, which turns the
        // splash off to test the main view.
        let draw = |app: &mut App, frame: u64| {
            app.frame = frame;
            let mut term = Terminal::new(TestBackend::new(110, 30)).unwrap();
            term.draw(|f| render::draw(f, app)).unwrap();
            term.backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>()
        };
        let out = draw(&mut app, 0);
        assert!(out.contains('#'), "the knife bitmap is drawn");
        assert!(
            out.contains("press any key to skip"),
            "the dismiss hint is drawn"
        );
        // The pre-analysis variant draws the same art with its own hint and an
        // indeterminate bar.
        {
            let mut term = Terminal::new(TestBackend::new(110, 30)).unwrap();
            term.draw(|f| splash::draw(f, f.area(), 7, true)).unwrap();
            let analysing = term
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(analysing.contains("press q to quit"));
            assert!(analysing.contains('#'));
        }
        // Advancing the frame clock changes the frame without panicking.
        for f in [2u64, 4, 6, 7, 9, 79] {
            assert!(draw(&mut app, f).contains('#'));
        }
    }

    #[test]
    fn any_key_dismisses_the_splash_without_acting_on_it() {
        let mut app = two_functions();
        assert!(app.splash, "a fresh app plays the splash");
        // `q` would quit and `/` would open a prompt; the splash must swallow
        // the first key so neither happens by accident.
        app.on_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(!app.splash, "the splash swallowed the key");
        assert!(!app.quit, "and the key did nothing else");
        assert!(app.prompt.is_none());
    }
}
