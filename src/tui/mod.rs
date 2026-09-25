//! The interactive view: a function list, a listing, and cross-references,
//! with your names and notes written straight through to the database.
//!
//! State and rendering are kept apart on purpose. Everything that decides what
//! happens lives in `App` and is driven by plain method calls, so the awkward
//! parts (navigation, filtering, the follow-and-return stack) can be tested
//! without a terminal; `render` only ever reads.

mod browser;
mod command;
pub mod explorer;
mod layout;
mod navigation;
/// Deterministic demo recorder for the README animation. Dev-only, so it
/// is compiled out of the published crate unless the feature is asked for.
#[cfg(feature = "record")]
pub mod record;
mod render;
pub use navigation::NavigationLocation;
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
use anyhow::{Context, Result};
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use std::collections::BTreeMap;
use std::io::stdout;
use std::time::{Duration, Instant};

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
    Callers,
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
    Command,
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
            Ask::Command => ":",
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
///
/// The target travels with the result rather than being cloned into the
/// worker. The main thread only reports progress while the analysis runs,
/// so it has no use for the image in the meantime, and a copy of it costs as
/// much resident memory as the file is large.
struct WorkResult {
    bin: Binary,
    bytes: Vec<u8>,
    db: Db,
    an: crate::analysis::engine::Analysis,
    sinks: Vec<crate::analysis::audit::Finding>,
    strings: BTreeMap<u64, Located>,
    driver: Option<crate::analysis::driver::DriverReport>,
}

/// Where the target lives on disk, so `:reload` can pick up external changes.
/// A session started from an injected image has no source and cannot reload.
#[derive(Debug, Clone)]
pub struct TargetSource {
    pub path: std::path::PathBuf,
    pub db_path: Option<std::path::PathBuf>,
}

/// What a reload worker computes; identical in shape to the startup pipeline.
struct ReloadOutcome {
    work: WorkResult,
    elapsed_ms: u128,
}

/// Re-read the target from disk and run the full startup analysis pipeline
/// on it. The annotation database follows content identity: an unchanged file
/// reloads into the same database, a changed file starts a fresh one.
fn load_target(source: &TargetSource) -> Result<WorkResult> {
    let file = source.path.to_string_lossy().to_string();
    let original = std::fs::read(&source.path)
        .with_context(|| format!("cannot read {}", source.path.display()))?;
    let original_bin = crate::formats::analyze(&file, &original)?;
    let db = Db::load(
        &crate::analysis::hashes::sha256_hex(&original),
        &file,
        source.db_path.as_deref().and_then(|p| p.to_str()),
    )?;
    let bytes = db.apply_patches(original)?;
    let bin = if db.patches.is_empty() {
        original_bin
    } else {
        crate::formats::analyze(&file, &bytes)
            .context("staged patches make the binary unparsable")?
    };
    if !crate::analysis::disasm::supported(bin.arch) {
        anyhow::bail!(
            "the interactive view needs x86, x64, or AArch64 disassembly; this is {}",
            bin.arch.label()
        );
    }
    let an = engine::analyze(&bin, &bytes, crate::ANALYSIS_BUDGET, &db);
    let mut sinks = crate::analysis::audit::run(&an, &bin, &bytes);
    sinks.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.reachable.cmp(&a.reachable))
            .then(a.addr.cmp(&b.addr))
    });
    let strings = listing::string_map(&bin, &bytes, engine::display_base(&bin));
    let driver = if crate::analysis::driver::plausibly_a_driver(&bin) {
        Some(crate::analysis::driver::report(&bin, &bytes, &an, &strings))
    } else {
        None
    };
    Ok(WorkResult {
        bin,
        bytes,
        db,
        an,
        sinks,
        strings,
        driver,
    })
}

/// One listing pane's full state: what it shows, where its cursor is, and its
/// own back/forward stacks. The active pane's state lives directly on `App`
/// (so the existing code keeps working); the inactive pane's lives here and
/// the two are swapped when the user switches columns.
#[derive(Debug, Clone, Default)]
pub struct ListingView {
    pub cur: Option<u64>,
    pub raw_file: bool,
    pub lines: Vec<Line>,
    pub cursor: usize,
    view_positions: navigation::ViewPositions,
    pub pseudo: bool,
    pub graph: bool,
    pub pseudo_lines: Vec<crate::analysis::ir::Line>,
    pub history: Vec<NavigationLocation>,
    pub future: Vec<NavigationLocation>,
    pub search: String,
}

/// A borrowed snapshot of one listing column, so the renderer can draw either
/// pane without caring which one currently owns the active state.
pub struct ListingViewRef<'a> {
    pub cur: Option<u64>,
    pub raw_file: bool,
    pub lines: &'a [Line],
    pub cursor: usize,
    pub pseudo: bool,
    pub graph: bool,
    pub pseudo_lines: &'a [crate::analysis::ir::Line],
    pub focused: bool,
}

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
    pub browser: Option<browser::Browser>,

    // ── listing (the ACTIVE pane; see `other` for the inactive column) ──
    pub cur: Option<u64>,
    /// The active listing uses on-disk offsets rather than image addresses.
    pub raw_file: bool,
    pub lines: Vec<Line>,
    pub cursor: usize,
    view_positions: navigation::ViewPositions,
    /// When set, the listing pane shows decompiled pseudocode for the current
    /// function instead of the disassembly.
    pub pseudo: bool,
    /// Show the current function as navigable CFG basic-block cards.
    pub graph: bool,
    /// The decompiled lines for the current function, rebuilt when it changes
    /// while pseudocode is showing.
    pub pseudo_lines: Vec<crate::analysis::ir::Line>,

    // ── split view ──
    /// Two listing columns side by side. The references pane is hidden while
    /// split; the second column takes its slot.
    pub split: bool,
    /// Which column currently owns the active state: left when true.
    pub active_is_left: bool,
    /// The inactive column's full state; swapped with the active fields when
    /// the user switches panes.
    pub other: ListingView,

    // ── the rest ──
    pub focus: Focus,
    pub pane_settings: layout::PaneSettings,
    pub prompt: Option<Prompt>,
    command_history: command::History,
    pub history: Vec<NavigationLocation>,
    pub future: Vec<NavigationLocation>,
    pub status: String,
    pub help: bool,
    pub help_scroll: usize,
    pub quit: bool,
    /// Cursor into the cross-reference list (a separate list pane, so it has a
    /// selection of its own like the other two).
    pub xsel: usize,
    pub reference_anchor: Option<u64>,
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

    // Legacy demo-recorder state; normal startup never enables the intro.
    /// Recorder frame counter. The interactive event loop does not advance it.
    pub frame: u64,
    /// Explicit legacy recording mode. Defaults to false in the workstation.
    pub splash: bool,

    // ── reload ──
    /// On-disk location of the target, set by the session entry point.
    pub source: Option<TargetSource>,
    /// The in-flight reload, if `:reload` is running its worker.
    reloading: Option<std::sync::mpsc::Receiver<Result<ReloadOutcome>>>,
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
            browser: None,
            cur: None,
            raw_file: false,
            lines: Vec::new(),
            cursor: 0,
            view_positions: navigation::ViewPositions::default(),
            pseudo: false,
            graph: false,
            pseudo_lines: Vec::new(),
            split: false,
            active_is_left: true,
            other: ListingView::default(),
            focus: Focus::Functions,
            pane_settings: layout::PaneSettings::default(),
            prompt: None,
            command_history: command::History::default(),
            history: Vec::new(),
            future: Vec::new(),
            status: String::new(),
            help: false,
            help_scroll: 0,
            quit: false,
            xsel: 0,
            reference_anchor: None,
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
            splash: false,
            source: None,
            reloading: None,
        };
        app.refilter();
        // Open something immediately: an empty right-hand pane makes the tool
        // look broken rather than ready.
        if let Some(&i) = app.order.first() {
            let addr = app.an.functions[i].addr;
            app.open(addr, false);
        } else {
            // No recovered functions is not a dead end: sections, strings and
            // raw bytes are still worth looking at.
            app.open_inspection_view();
        }
        app
    }

    /// A target with no recovered functions still opens: the first mapped
    /// bytes as a data view, so sections, strings and notes all still work.
    fn open_inspection_view(&mut self) {
        let address = self
            .bin
            .entry
            .checked_add(self.base)
            .filter(|&a| self.is_mapped(a))
            .or_else(|| {
                self.bin
                    .sections
                    .iter()
                    .find(|s| s.file_size > 0)
                    .map(|s| self.base + s.vaddr)
            })
            .filter(|&a| self.is_mapped(a));
        match address {
            Some(a) => {
                self.open(a, false);
                self.status =
                    "no functions recovered; opened mapped bytes (:strings/:sections still work)"
                        .into();
            }
            None => {
                self.status =
                    "no functions or mapped data recovered; try :strings or :sections".into();
            }
        }
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
                    if let Some(previous) = self.navigation_location() {
                        self.history.push(previous);
                        self.future.clear();
                    }
                }
                self.lines = listing::data_view(&self.bin, self.base, &self.bytes, addr);
                self.raw_file = false;
                self.pseudo = false;
                self.graph = false;
                self.pseudo_lines.clear();
                self.view_positions = navigation::ViewPositions::default();
                self.cur = Some(addr);
                self.reference_anchor = None;
                self.cursor = 0;
                self.clamp_xsel();
                return;
            }
            self.status = format!("0x{addr:x} is not inside a recovered function");
            return;
        };

        if push {
            if let Some(previous) = self.navigation_location() {
                self.history.push(previous);
                self.future.clear();
            }
        }

        if self.cur != Some(faddr) {
            self.view_positions = navigation::ViewPositions::default();
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
        self.raw_file = false;
        self.cur = Some(faddr);
        self.reference_anchor = None;
        self.clamp_xsel();
        // Land on the requested address, not merely the top of the function.
        self.cursor = self
            .lines
            .iter()
            .position(|l| l.addr() == addr)
            .unwrap_or(0);
        self.view_positions.disassembly = self.cursor;
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
            self.cursor = self
                .view_positions
                .pseudocode
                .min(self.pseudo_lines.len().saturating_sub(1));
        }
    }

    /// Open bytes by their actual on-disk offset. No image mapping is required
    /// and every rendered row remains explicitly labelled as a file offset.
    pub fn open_file_offset(&mut self, offset: u64, push: bool) {
        let window = match crate::api::listing::file_hex_window(
            &self.bin,
            &self.bytes,
            self.base,
            crate::api::listing::FileHexQuery {
                file_offset: crate::address::FileOffset(offset),
                length: 512,
            },
        ) {
            Ok(window) => window,
            Err(error) => {
                self.status = format!("cannot open file offset 0x{offset:x}: {error:#}");
                return;
            }
        };
        if push {
            if let Some(previous) = self.navigation_location() {
                self.history.push(previous);
                self.future.clear();
            }
        }
        self.lines = window
            .rows
            .into_iter()
            .map(|row| {
                let mappings = if row.mappings.is_empty() {
                    String::new()
                } else {
                    format!(
                        "  [{}]",
                        row.mappings
                            .iter()
                            .map(|mapping| format!(
                                "{} VA 0x{:x}",
                                mapping.region,
                                mapping.address.get()
                            ))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                Line::Data {
                    addr: row.file_offset.get(),
                    text: format!("{:<47}  |{}|{mappings}", row.hex, row.ascii),
                }
            })
            .collect();
        self.cur = Some(offset);
        self.raw_file = true;
        self.pseudo = false;
        self.graph = false;
        self.pseudo_lines.clear();
        self.view_positions = navigation::ViewPositions::default();
        self.reference_anchor = None;
        self.cursor = 0;
        self.status = format!("raw file bytes at OFF 0x{offset:x}; mapped VAs are annotations");
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
        (!self.raw_file)
            .then_some(self.cur)
            .flatten()
            .and_then(|addr| self.an.find_function(addr))
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
        if !self.pseudo {
            self.recompute_pseudo();
            if self.pseudo_lines.is_empty() {
                self.status = "no pseudocode here: open a recovered function first".into();
                return;
            }
        }
        self.remember_view_cursor();
        self.graph = false;
        self.pseudo = !self.pseudo;
        self.cursor = if self.pseudo {
            self.view_positions.pseudocode
        } else {
            self.view_positions.disassembly
        }
        .min(self.listing_len().saturating_sub(1));
    }

    /// Switch between the linear listing and the function's control-flow graph.
    pub fn toggle_graph(&mut self) {
        if self.graph {
            let address = self
                .current_function()
                .and_then(|f| f.blocks.get(self.cursor))
                .map(|block| block.start);
            self.graph = false;
            self.cursor = address
                .and_then(|address| self.lines.iter().position(|line| line.addr() == address))
                .unwrap_or(self.view_positions.disassembly)
                .min(self.lines.len().saturating_sub(1));
            return;
        }
        if self.current_function().is_none() {
            self.status = "no graph here: open a recovered function first".into();
            return;
        }
        self.remember_view_cursor();
        let address = self
            .lines
            .get(self.view_positions.disassembly)
            .map(Line::addr);
        let block = self
            .current_function()
            .and_then(|f| {
                f.blocks.iter().position(|block| {
                    address.is_some_and(|address| address >= block.start && address < block.end)
                })
            })
            .unwrap_or(0);
        self.pseudo = false;
        self.graph = true;
        self.cursor = block;
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

    // ── split view ──

    /// The active column as the renderer wants it: the fields on `App`
    /// themselves, marked focused when the listing has input focus.
    pub fn active_view(&self) -> ListingViewRef<'_> {
        ListingViewRef {
            cur: self.cur,
            raw_file: self.raw_file,
            lines: &self.lines,
            cursor: self.cursor,
            pseudo: self.pseudo,
            graph: self.graph,
            pseudo_lines: &self.pseudo_lines,
            focused: self.focus == Focus::Listing,
        }
    }

    /// The inactive column, drawn without the focus marker.
    pub fn other_view(&self) -> ListingViewRef<'_> {
        ListingViewRef {
            cur: self.other.cur,
            raw_file: self.other.raw_file,
            lines: &self.other.lines,
            cursor: self.other.cursor,
            pseudo: self.other.pseudo,
            graph: self.other.graph,
            pseudo_lines: &self.other.pseudo_lines,
            focused: false,
        }
    }

    /// Exchange the two columns' state. The now-active pane is rebuilt from
    /// the current analysis so edits made while it was inactive show up.
    fn swap_views(&mut self) {
        std::mem::swap(&mut self.cur, &mut self.other.cur);
        std::mem::swap(&mut self.raw_file, &mut self.other.raw_file);
        std::mem::swap(&mut self.lines, &mut self.other.lines);
        std::mem::swap(&mut self.cursor, &mut self.other.cursor);
        std::mem::swap(&mut self.view_positions, &mut self.other.view_positions);
        std::mem::swap(&mut self.pseudo, &mut self.other.pseudo);
        std::mem::swap(&mut self.graph, &mut self.other.graph);
        std::mem::swap(&mut self.pseudo_lines, &mut self.other.pseudo_lines);
        std::mem::swap(&mut self.history, &mut self.other.history);
        std::mem::swap(&mut self.future, &mut self.other.future);
        std::mem::swap(&mut self.search, &mut self.other.search);
        self.active_is_left = !self.active_is_left;
        self.relist();
    }

    /// Clone the active pane into a second column at the same location.
    pub fn split_clone(&mut self) {
        if self.split {
            self.status = "already split; :only returns to one listing".into();
            return;
        }
        if self.cur.is_none() {
            self.status = "open a function or a data view before splitting".into();
            return;
        }
        self.other = ListingView {
            cur: self.cur,
            raw_file: self.raw_file,
            lines: self.lines.clone(),
            cursor: self.cursor,
            view_positions: self.view_positions,
            pseudo: self.pseudo,
            graph: self.graph,
            pseudo_lines: self.pseudo_lines.clone(),
            history: self.history.clone(),
            future: self.future.clone(),
            search: self.search.clone(),
        };
        self.split = true;
        self.active_is_left = true;
        self.status = "split; Tab switches panes, :compare pins a function, :only closes".into();
    }

    /// Pin a function — the current one, or a selector's — into the other
    /// column, so the active pane can roam while the pinned one stays put.
    pub fn compare(&mut self, selector: Option<String>) {
        let address = match selector.as_deref() {
            Some(text) => match self.resolve_goto(text) {
                Ok(address) => address,
                Err(error) => {
                    self.status = error.to_string();
                    return;
                }
            },
            None => match self.cur {
                Some(address) => address,
                None => {
                    self.status = "open a function before comparing".into();
                    return;
                }
            },
        };
        let Some(view) = self.build_listing_view(address) else {
            self.status = format!("0x{address:x} has no listing to pin");
            return;
        };
        self.other = view;
        self.split = true;
        self.status = format!(
            "comparing against {}; Tab switches panes",
            self.an.label(address)
        );
    }

    /// Build a standalone listing column for an address: its function when
    /// there is one, its mapped bytes otherwise.
    fn build_listing_view(&self, address: u64) -> Option<ListingView> {
        let target = self
            .an
            .find_function(address)
            .or_else(|| self.an.function_at(address))
            .map(|f| f.addr);
        let (cur, lines) = if let Some(faddr) = target {
            let f = self.an.find_function(faddr)?;
            (
                faddr,
                listing::function(
                    &self.an,
                    f,
                    &self.db,
                    self.base,
                    &self.strings,
                    self.driver.as_ref().map(|d| &d.listing_hints),
                ),
            )
        } else if self.is_mapped(address) {
            (
                address,
                listing::data_view(&self.bin, self.base, &self.bytes, address),
            )
        } else {
            return None;
        };
        let cursor = lines.iter().position(|l| l.addr() == address).unwrap_or(0);
        Some(ListingView {
            cur: Some(cur),
            lines,
            cursor,
            ..Default::default()
        })
    }

    /// Collapse to one listing, keeping whichever pane is active.
    pub fn close_split(&mut self) {
        if !self.split {
            self.status = "not split".into();
            return;
        }
        self.split = false;
        self.other = ListingView::default();
        self.focus = Focus::Listing;
        self.status = "back to one listing".into();
    }

    /// Tab in split mode walks Functions → left listing → right listing and
    /// back (and the reverse); the references pane is hidden while split, so
    /// the cycle skips it.
    fn cycle_split_focus(&mut self, reverse: bool) {
        if reverse {
            match self.focus {
                Focus::Listing if !self.active_is_left => self.swap_views(),
                Focus::Listing => {
                    if self.pane_settings.functions {
                        self.focus = Focus::Functions;
                    } else {
                        self.swap_views();
                    }
                }
                _ => {
                    self.focus = Focus::Listing;
                    if self.active_is_left {
                        self.swap_views();
                    }
                }
            }
        } else {
            match self.focus {
                Focus::Functions => {
                    self.focus = Focus::Listing;
                    if !self.active_is_left {
                        self.swap_views();
                    }
                }
                Focus::Listing if self.active_is_left => self.swap_views(),
                Focus::Listing => {
                    if self.pane_settings.functions {
                        self.focus = Focus::Functions;
                    } else {
                        self.swap_views();
                    }
                }
                Focus::Xrefs => {
                    self.focus = Focus::Listing;
                    if !self.active_is_left {
                        self.swap_views();
                    }
                }
            }
        }
    }

    pub fn back(&mut self) {
        let Some(location) = self.history.pop() else {
            self.status = "nothing to go back to".into();
            return;
        };
        if let Some(current) = self.navigation_location() {
            self.future.push(current);
        }
        self.restore_navigation(location);
    }

    pub fn forward(&mut self) {
        let Some(location) = self.future.pop() else {
            self.status = "nothing to go forward to".into();
            return;
        };
        if let Some(current) = self.navigation_location() {
            self.history.push(current);
        }
        self.restore_navigation(location);
    }

    fn remember_view_cursor(&mut self) {
        self.view_positions = self.current_view_positions();
    }

    fn current_view_positions(&self) -> navigation::ViewPositions {
        let mut positions = self.view_positions;
        if self.pseudo {
            positions.pseudocode = self.cursor;
        } else if !self.graph {
            positions.disassembly = self.cursor;
        }
        positions
    }

    fn navigation_location(&self) -> Option<NavigationLocation> {
        self.cur.map(|address| NavigationLocation {
            address,
            file_offset: self.raw_file,
            cursor: self.cursor,
            positions: self.current_view_positions(),
            pseudo: self.pseudo,
            graph: self.graph,
            focus: self.focus,
            reference_view: self.refview,
            reference_cursor: self.xsel,
            reference_anchor: self.reference_anchor,
        })
    }

    fn restore_navigation(&mut self, location: NavigationLocation) {
        self.pseudo = location.pseudo;
        self.graph = location.graph;
        if location.file_offset {
            self.open_file_offset(location.address, false);
        } else {
            self.open(location.address, false);
        }
        self.view_positions = location.positions;
        self.cursor = location.cursor.min(self.listing_len().saturating_sub(1));
        self.focus = location.focus;
        self.refview = location.reference_view;
        self.xsel = location.reference_cursor;
        self.reference_anchor = location.reference_anchor;
        self.clamp_xsel();
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let len = self.listing_len();
        if len == 0 {
            return;
        }
        self.cursor = self.cursor.saturating_add_signed(delta).min(len - 1);
    }

    fn page_raw_file(&mut self, forward: bool) {
        let Some(start) = self.cur else {
            return;
        };
        let next = if forward {
            start.checked_add(512)
        } else {
            Some(start.saturating_sub(512))
        };
        let Some(next) = next else {
            self.status = "raw file offset overflow".into();
            return;
        };
        if next == start {
            self.status = "already at the beginning of the file".into();
            return;
        }
        self.open_file_offset(next, true);
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

    /// Resolve a goto target. A bare value is a symbol or a static VA (the
    /// space addresses are displayed in); `va:0x..` pins the value to that
    /// space even when a symbol shares the text, and `off:0x..` (or
    /// `file:0x..`) reads the value as a file offset and converts it through
    /// the section table.
    fn resolve_goto(&self, text: &str) -> Result<u64> {
        let text = text.trim();
        if let Some(rest) = text
            .strip_prefix("off:")
            .or_else(|| text.strip_prefix("file:"))
        {
            let offset = parse_hex(rest)?;
            return engine::off_to_va(&self.bin, self.base, offset).ok_or_else(|| {
                anyhow::anyhow!("file offset 0x{offset:x} is not in a file-backed section")
            });
        }
        if let Some(rest) = text.strip_prefix("va:") {
            return parse_hex(rest)
                .map_err(|_| anyhow::anyhow!("bad static VA {rest:?}; use va:0xADDRESS"));
        }
        crate::api::navigation::resolve_address_in(&self.an, text).map(|a| a.get())
    }

    // ── sinks / driver views ──

    /// Cycle the left pane: functions → sinks → driver → analyst types → back.
    pub fn toggle_sinks(&mut self) {
        self.browser = None;
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
        if let Some(browser) = &mut self.browser {
            browser.filter(text);
            return;
        }
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
        if self.focus == Focus::Listing && self.raw_file {
            return None;
        }
        if self.focus == Focus::Functions {
            if let Some(browser) = &self.browser {
                return browser
                    .selected()
                    .and_then(|row| row.address)
                    .map(|address| address.get());
            }
        }
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
        if self.raw_file {
            self.status =
                "raw file rows are not control-flow instructions; use D on an ELF catalog row"
                    .into();
            return;
        }
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
                    None => format!("0x{t:x} is not a recovered function"),
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
        if self.raw_file {
            return 0;
        }
        if self.focus == Focus::Xrefs {
            if let Some(address) = self.reference_anchor {
                return address;
            }
        }
        self.cursor_addr().or(self.cur).unwrap_or(0)
    }

    /// Project the shared reference query into navigable terminal rows.
    pub fn xref_rows(&self) -> Vec<XRow> {
        use crate::api::references::{query_in, ReferenceView};
        let (address, view) = match self.refview {
            RefView::To => (self.xref_at(), ReferenceView::Xrefs),
            RefView::Callers => (self.cur.unwrap_or(0), ReferenceView::Callers),
            RefView::From => (self.cur.unwrap_or(0), ReferenceView::Callees),
        };
        query_in(&self.an, crate::address::StaticVa(address), view)
            .into_iter()
            .map(|row| XRow {
                jump: if view == ReferenceView::Callees {
                    row.target.get()
                } else {
                    row.source.get()
                },
                site: row.source.get(),
                kind: row.kind.label(),
                label: if view == ReferenceView::Callees {
                    row.target_label
                } else {
                    row.source_label
                },
            })
            .collect()
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
            RefView::Callers => RefView::From,
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
                None => format!("0x{t:x} is not in a recovered function"),
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
            Ask::Command => {
                self.command_history.record(&text);
                self.execute_command(&text);
            }
            Ask::Filter => {
                self.set_filter(text);
            }
            Ask::Goto => match self.resolve_goto(&text) {
                Ok(address) => self.open(address, true),
                Err(error) => self.status = error.to_string(),
            },
            Ask::Search => self.search_listing(text),
            Ask::Name => {
                if text.is_empty() {
                    let n = self.db.clear_name(stored);
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
                    self.db.clear_note(stored);
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
        self.an.rebuild_indexes();
        self.refilter();
        self.relist();
    }

    fn relist(&mut self) {
        if self.raw_file {
            if let Some(offset) = self.cur {
                let cursor = self.cursor;
                self.open_file_offset(offset, false);
                self.cursor = cursor.min(self.lines.len().saturating_sub(1));
            }
            self.refresh_catalog();
            return;
        }
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
        self.refresh_catalog();
    }

    pub fn reanalyze(&mut self) {
        self.an = engine::analyze(&self.bin, &self.bytes, 2_000_000, &self.db);
        self.refilter();
        self.relist();
    }

    // ── reload from disk ──

    /// Start a background re-read of the target file. Unlike `r`, which
    /// re-analyses the bytes already in memory after an edit, `:reload` picks
    /// up what another tool wrote to the file. The workspace keeps running
    /// until `poll_reload` applies the result; a failed reload changes
    /// nothing but the status line.
    pub fn reload(&mut self) {
        if self.reloading.is_some() {
            self.status = "reload already running".into();
            return;
        }
        let Some(source) = self.source.clone() else {
            self.status = "no on-disk target; this session cannot reload".into();
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let _ = tx.send(load_target(&source).map(|work| ReloadOutcome {
                work,
                elapsed_ms: started.elapsed().as_millis(),
            }));
        });
        self.reloading = Some(rx);
        self.status = "reloading from disk...".into();
    }

    /// Whether a reload worker is in flight; the event loop polls instead of
    /// blocking while this is true.
    pub fn is_reloading(&self) -> bool {
        self.reloading.is_some()
    }

    /// Collect a finished reload, if there is one. Applied state replaces the
    /// session wholesale; a failure keeps the old session untouched.
    pub fn poll_reload(&mut self) {
        let Some(rx) = &self.reloading else { return };
        let outcome = match rx.try_recv() {
            Ok(outcome) => outcome,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(anyhow::anyhow!("the reload worker died"))
            }
        };
        self.reloading = None;
        match outcome {
            Ok(outcome) => self.apply_reload(outcome),
            Err(error) => {
                self.status = format!("reload failed, kept the old session: {error:#}");
            }
        }
    }

    fn apply_reload(&mut self, outcome: ReloadOutcome) {
        let WorkResult {
            bin,
            bytes,
            db,
            an,
            sinks,
            strings,
            driver,
        } = outcome.work;
        let before = self.an.functions.len();
        self.bin = bin;
        self.bytes = bytes;
        self.db = db;
        self.an = an;
        self.sinks = sinks;
        self.strings = strings;
        self.driver = driver;
        self.base = engine::display_base(&self.bin);
        // Locations from the old image may not exist in the new one; stale
        // jumps are worse than a cleared stack.
        self.history.clear();
        self.future.clear();
        self.cur = None;
        self.lines.clear();
        self.cursor = 0;
        self.pseudo = false;
        self.graph = false;
        self.pseudo_lines.clear();
        self.view_positions = navigation::ViewPositions::default();
        self.prompt = None;
        self.browser = None;
        self.reference_anchor = None;
        self.xsel = 0;
        self.ssel = 0;
        self.dsel = 0;
        self.tsel = 0;
        self.search.clear();
        // The other column belongs to the old image as surely as the history
        // does; the workspace comes back as one listing.
        self.split = false;
        self.other = ListingView::default();
        // Pane sizes, focus, filter and the left-pane mode survive: they are
        // how the analyst arranged their desk, not facts about the target.
        self.refilter();
        self.clamp_xsel();
        self.clamp_dsel();
        self.clamp_tsel();
        if let Some(&i) = self.order.first() {
            let addr = self.an.functions[i].addr;
            self.open(addr, false);
        } else {
            self.open_inspection_view();
        }
        self.focus = Focus::Functions;
        self.status = format!(
            "reloaded in {}ms: {} functions (was {})",
            outcome.elapsed_ms,
            self.an.functions.len(),
            before
        );
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

        // While a reload runs, the workspace being replaced must not be
        // navigated; only leaving is allowed.
        if self.reloading.is_some() {
            let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                || (key.code == KeyCode::Char('c')
                    && key.modifiers.contains(KeyModifiers::CONTROL));
            if quit {
                self.quit = true;
            }
            return;
        }

        if let Some(p) = &mut self.prompt {
            match key.code {
                KeyCode::Up if p.ask == Ask::Command => {
                    p.input = self.command_history.previous(&p.input);
                }
                KeyCode::Down if p.ask == Ask::Command => {
                    p.input = self.command_history.next(&p.input);
                }
                KeyCode::Tab if p.ask == Ask::Command => {
                    let matches = command::complete(&p.input);
                    if matches.len() == 1 {
                        p.input = format!("{} ", matches[0]);
                    } else {
                        self.status = matches.join("  ");
                    }
                }
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
            let max = render::help_max_scroll(self.dims.0, self.dims.1);
            let page = render::help_page_size(self.dims.0, self.dims.1);
            self.help_scroll = self.help_scroll.min(max);
            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.quit = true
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1).min(max)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => {
                    self.help_scroll = self.help_scroll.saturating_add(page).min(max)
                }
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(page),
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = max,
                KeyCode::Esc | KeyCode::Char('?') => self.help = false,
                _ => {}
            }
            return;
        }

        self.status.clear();
        let page = 20isize;
        match key.code {
            KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => self.back(),
            KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => self.forward(),
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => self.quit = true,
            KeyCode::Char('?') => {
                self.help_scroll = 0;
                self.help = true;
            }
            KeyCode::Char('b') => self.execute_command("bookmark"),
            KeyCode::Char('+') | KeyCode::Char('=') => self.resize_pane(4),
            KeyCode::Char('-') => self.resize_pane(-4),
            KeyCode::Char('z') => self.toggle_pane_zoom(),
            KeyCode::Char(':') => {
                self.command_history.reset();
                self.ask(Ask::Command);
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if self.focus == Focus::Listing {
                    self.reference_anchor = Some(self.xref_at());
                }
                let reverse =
                    key.code == KeyCode::BackTab || key.modifiers.contains(KeyModifiers::SHIFT);
                if self.split {
                    self.cycle_split_focus(reverse);
                    return;
                }
                let references = self.pane_settings.references && !self.xref_rows().is_empty();
                self.focus = if reverse {
                    match self.focus {
                        Focus::Listing if self.pane_settings.functions => Focus::Functions,
                        Focus::Listing | Focus::Functions if references => Focus::Xrefs,
                        _ => Focus::Listing,
                    }
                } else {
                    match self.focus {
                        Focus::Functions => Focus::Listing,
                        Focus::Listing if references => Focus::Xrefs,
                        Focus::Listing | Focus::Xrefs if self.pane_settings.functions => {
                            Focus::Functions
                        }
                        _ => Focus::Listing,
                    }
                };
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
            KeyCode::PageDown if self.focus == Focus::Listing && self.raw_file => {
                if self.cursor.saturating_add(page as usize) >= self.lines.len() {
                    self.page_raw_file(true);
                } else {
                    self.step(page);
                }
            }
            KeyCode::PageUp if self.focus == Focus::Listing && self.raw_file => {
                if self.cursor < page as usize {
                    self.page_raw_file(false);
                } else {
                    self.step(-page);
                }
            }
            KeyCode::PageDown => self.step(page),
            KeyCode::PageUp => self.step(-page),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Char('O')
                if self.focus == Focus::Functions
                    && self
                        .browser
                        .as_ref()
                        .is_some_and(|browser| browser.catalog.is_elf_structure()) =>
            {
                self.open_browser_record()
            }
            KeyCode::Char('D')
                if self.focus == Focus::Functions
                    && self
                        .browser
                        .as_ref()
                        .is_some_and(|browser| browser.catalog.is_elf_structure()) =>
            {
                self.open_browser_disassembly()
            }
            KeyCode::Enter if self.focus == Focus::Functions && self.browser.is_some() => {
                self.open_browser_selection()
            }
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
            KeyCode::Char('x') => {
                if self.split {
                    self.status = "references are hidden while split; :only closes a pane".into();
                } else {
                    self.toggle_refs();
                }
            }
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
        if self.focus == Focus::Functions {
            if let Some(browser) = &mut self.browser {
                browser.step(delta);
                return;
            }
        }
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
            Ask::Command => String::new(),
            Ask::Filter if self.browser.is_some() => self.browser.as_ref().unwrap().filter.clone(),
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
                .map(|instruction| format_bytes(instruction.bytes()))
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

    /// The rect of the column that owns the active listing state: the left
    /// column normally, the right one after a pane switch in split mode.
    fn active_listing_rect(&self, panes: &layout::Panes) -> ratatui::layout::Rect {
        if self.split && !self.active_is_left {
            panes.listing_right
        } else {
            panes.listing
        }
    }

    /// The pane a terminal position belongs to, given the size stored before
    /// the last frame. The layout mirrors `render::draw`, kept in one place so
    /// the two cannot disagree.
    pub fn pane_at(&self, column: u16, row: u16) -> Option<(Focus, usize)> {
        let panes = self.panes(ratatui::layout::Rect::new(0, 0, self.dims.0, self.dims.1));
        let point = ratatui::layout::Position::new(column, row);
        let listing_rect = self.active_listing_rect(&panes);
        let (focus, area, len, selection) = if panes.functions.contains(point) {
            let (len, selection) = match self.left {
                LeftView::Functions => (self.order.len(), self.sel),
                LeftView::Sinks => (self.sinks.len(), self.ssel),
                LeftView::Driver => (self.driver_rows().len(), self.dsel),
                LeftView::Types => (self.type_rows().len(), self.tsel),
            };
            (Focus::Functions, panes.functions, len, selection)
        } else if panes.references.contains(point) {
            (
                Focus::Xrefs,
                panes.references,
                self.xref_rows().len(),
                self.xsel,
            )
        } else if listing_rect.contains(point) {
            (
                Focus::Listing,
                listing_rect,
                self.listing_len(),
                self.cursor,
            )
        } else {
            return None;
        };
        let inner = area.inner(ratatui::layout::Margin::new(1, 1));
        if !inner.contains(point) {
            return None;
        }
        let viewport = match focus {
            Focus::Functions if self.browser.is_none() && self.left == LeftView::Functions => {
                render::viewport_start(selection, len, usize::from(inner.height))
            }
            Focus::Listing if !self.graph => {
                render::viewport_start(selection, len, usize::from(inner.height))
            }
            Focus::Xrefs => render::viewport_start(selection, len, usize::from(inner.height)),
            _ => selection.saturating_sub(usize::from(inner.height).saturating_sub(1)),
        };
        let mut idx = usize::from(row - inner.y) + viewport;
        if focus == Focus::Listing && self.graph {
            let inspector_height = if inner.height >= 9 { 6 } else { 0 };
            idx = self
                .graph_block_at_point(
                    column - inner.x,
                    row - inner.y,
                    inner.width,
                    inner.height.saturating_sub(inspector_height),
                )
                .unwrap_or(self.cursor);
        }
        Some((focus, idx.min(len.saturating_sub(1))))
    }

    /// In split mode, a click or wheel turn over the inactive column makes it
    /// active first, so the pane under the mouse is the one that responds.
    fn activate_column_at(&mut self, column: u16, row: u16) {
        if !self.split {
            return;
        }
        let panes = self.panes(ratatui::layout::Rect::new(0, 0, self.dims.0, self.dims.1));
        let point = ratatui::layout::Position::new(column, row);
        let over_right = panes.listing_right.contains(point);
        if over_right == self.active_is_left && (over_right || panes.listing.contains(point)) {
            self.focus = Focus::Listing;
            self.swap_views();
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        if self.help {
            let max = render::help_max_scroll(self.dims.0, self.dims.1);
            match m.kind {
                MouseEventKind::ScrollUp => self.help_scroll = self.help_scroll.saturating_sub(1),
                MouseEventKind::ScrollDown => {
                    self.help_scroll = self.help_scroll.saturating_add(1).min(max)
                }
                _ => {}
            }
            return;
        }
        self.activate_column_at(m.column, m.row);
        match m.kind {
            MouseEventKind::ScrollUp => self.step(-1),
            MouseEventKind::ScrollDown => self.step(1),
            MouseEventKind::Down(MouseButton::Left) => {
                let Some((focus, idx)) = self.pane_at(m.column, m.row) else {
                    return;
                };
                self.focus = focus;
                if focus == Focus::Functions && self.browser.is_some() {
                    let panes =
                        self.panes(ratatui::layout::Rect::new(0, 0, self.dims.0, self.dims.1));
                    let inner = panes.functions.inner(ratatui::layout::Margin::new(1, 1));
                    if let Some(browser) = &mut self.browser {
                        let height = usize::from(inner.height).div_ceil(2).max(1);
                        let start = render::viewport_start(
                            browser.selection,
                            browser.visible.len(),
                            height,
                        );
                        browser.selection = (start
                            + usize::from(m.row.saturating_sub(inner.y)) / 2)
                            .min(browser.visible.len().saturating_sub(1));
                    }
                    self.open_browser_selection();
                    return;
                }
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

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Hexadecimal, with or without a `0x` prefix, matching the rest of the CLI.
fn parse_hex(text: &str) -> Result<u64> {
    let text = text.trim();
    let raw = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(raw, 16).map_err(|_| anyhow::anyhow!("bad hexadecimal value {text:?}"))
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
/// Analysis runs on a worker thread with an elapsed-time status, so opening a
/// large binary leaves the terminal responsive;
/// `q` / Esc / Ctrl-C quit even while it is still working.
pub fn run(source: TargetSource, bin: Binary, bytes: Vec<u8>, db: Db, title: String) -> Result<()> {
    // Keep initial analysis, string mapping and driver reporting off the UI thread.
    let (tx, rx) = std::sync::mpsc::channel::<WorkResult>();
    std::thread::spawn(move || {
        let an = engine::analyze(&bin, &bytes, crate::ANALYSIS_BUDGET, &db);
        let mut sinks = crate::analysis::audit::run(&an, &bin, &bytes);
        sinks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.reachable.cmp(&a.reachable))
                .then(a.addr.cmp(&b.addr))
        });
        let strings = listing::string_map(&bin, &bytes, engine::display_base(&bin));
        let driver = if crate::analysis::driver::plausibly_a_driver(&bin) {
            Some(crate::analysis::driver::report(&bin, &bytes, &an, &strings))
        } else {
            None
        };
        let _ = tx.send(WorkResult {
            bin,
            bytes,
            db,
            an,
            sinks,
            strings,
            driver,
        });
    });

    // `try_init` rather than `init`, so running this with output piped fails
    // with a sentence instead of a panic. It installs a panic hook that
    // restores the terminal, so a crash cannot leave the shell in raw mode.
    let mut term = ratatui::try_init()
        .map_err(|e| anyhow::anyhow!("cannot start the interactive view: {e}"))?;
    let _ = ratatui::crossterm::execute!(&mut stdout(), event::EnableMouseCapture);

    // No invented percent complete: the worker does not expose work-unit counts.
    let started = Instant::now();
    let ready: Result<Option<WorkResult>> = 'work: loop {
        if let Err(e) = term.draw(|f| render::loading(f, &title, started.elapsed().as_secs())) {
            break 'work Err(e.into());
        }
        match rx.try_recv() {
            Ok(ready) => break 'work Ok(Some(ready)),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                break 'work Err(anyhow::anyhow!("the analysis worker died"));
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        match event::poll(Duration::from_millis(200)) {
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

    let WorkResult {
        bin,
        bytes,
        db,
        an,
        sinks,
        strings,
        driver,
    } = match ready {
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
    // Open the usable workspace immediately. No intro replay or idle animation.
    // A target with no recovered functions is still inspectable: the workspace
    // opens on its mapped bytes and the catalogs stay available.
    let mut app = App::new(bin, bytes, db, an, sinks, strings, driver, title);
    app.source = Some(source);
    let res = loop {
        if let Ok(area) = term.size() {
            app.dims = (area.width, area.height);
        }
        if let Err(e) = term.draw(|f| render::draw(f, &app)) {
            break Err(e.into());
        }
        app.poll_reload();
        if app.is_reloading() {
            // A reload has a worker in flight: poll with a timeout so the
            // result is applied promptly instead of waiting for input.
            match event::poll(Duration::from_millis(100)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(k)) => app.on_key(k),
                    Ok(Event::Mouse(_)) | Ok(_) => {}
                    Err(e) => break Err(e.into()),
                },
                Ok(false) => {}
                Err(e) => break Err(e.into()),
            }
        } else {
            // No background work remains: block until input/resize instead of redrawing idle frames.
            match event::read() {
                Ok(Event::Key(k)) => app.on_key(k),
                Ok(Event::Mouse(m)) => app.on_mouse(m),
                Ok(_) => {}
                Err(e) => break Err(e.into()),
            }
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

    fn elf_app() -> App {
        let bytes = crate::formats::fixture::elf_with_plt_call();
        let bin = crate::formats::analyze("fixture.elf", &bytes).unwrap();
        let db = Db::default();
        let an = engine::analyze(&bin, &bytes, 100_000, &db);
        let sinks = ranked_sinks(&an, &bin, &bytes);
        let strings = listing::string_map(&bin, &bytes, engine::display_base(&bin));
        App::new(bin, bytes, db, an, sinks, strings, None, "elf".into())
    }

    #[test]
    fn elf_catalogs_open_real_file_offsets_and_restore_static_history() {
        let mut app = elf_app();
        let origin = app.navigation_location().unwrap();
        app.execute_command("headers");
        assert_eq!(
            app.browser.as_ref().unwrap().catalog,
            browser::Catalog::ElfHeaders
        );
        assert_eq!(app.browser.as_ref().unwrap().rows[0].label, "EI_MAG0");
        app.open_browser_selection();
        assert!(app.raw_file);
        assert_eq!(app.cur, Some(0));
        assert!(matches!(
            app.lines.first(),
            Some(Line::Data { addr: 0, .. })
        ));
        assert_eq!(app.cursor_addr(), None);
        app.page_raw_file(true);
        assert_eq!(app.cur, Some(512));
        assert!(app.raw_file);
        app.back();
        assert_eq!(app.cur, Some(0));
        app.back();
        assert_eq!(app.navigation_location().unwrap(), origin);

        app.execute_command("segments");
        assert!(!app.browser.as_ref().unwrap().rows.is_empty());
        app.open_browser_record();
        assert!(app.raw_file);
        assert_eq!(
            app.cur,
            app.browser.as_ref().unwrap().rows[0]
                .record_offset
                .map(|offset| offset.get())
        );
    }

    #[test]
    fn elf_catalog_commands_reject_non_elf_without_changing_navigation() {
        let mut app = two_functions();
        app.bin.format = Format::Pe;
        let origin = app.navigation_location().unwrap();
        app.execute_command("headers");
        assert!(app.status.contains("requires an ELF file"));
        assert!(app.browser.is_none());
        assert_eq!(app.navigation_location().unwrap(), origin);
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
    fn navigation_restores_view_and_forward_branch() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.toggle_pseudo();
        app.focus = Focus::Xrefs;
        app.cursor = app.listing_len().saturating_sub(1);
        let origin = app.navigation_location().unwrap();
        app.open(0x100b, true);
        app.toggle_pseudo();
        app.toggle_graph();
        app.focus = Focus::Listing;
        let destination = app.navigation_location().unwrap();
        app.back();
        assert_eq!(app.navigation_location().unwrap(), origin);
        app.forward();
        assert_eq!(app.navigation_location().unwrap(), destination);
        app.back();
        app.open(0x100b, true);
        assert!(
            app.future.is_empty(),
            "new navigation replaces forward branch"
        );
    }

    #[test]
    fn command_prompt_executes_completes_and_recalls() {
        let mut app = two_functions();
        app.splash = false;
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for ch in "function 100b".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.cur, Some(0x100b));
        assert_eq!(app.focus, Focus::Listing);
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.prompt.as_ref().unwrap().input, "function 100b");
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        for ch in "de".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.prompt.as_ref().unwrap().input, "decompile ");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.pseudo);
        app.execute_command("disasm");
        assert!(!app.pseudo && !app.graph);
        app.execute_command("cfg");
        assert!(app.graph);
        app.execute_command("unsupported");
        assert!(app.status.contains("unknown command"));
    }

    #[test]
    fn references_keep_the_selected_address_when_focus_changes() {
        let mut app = two_functions();
        app.splash = false;
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.cursor = app.lines.len().saturating_sub(1);
        let address = app.cursor_addr().unwrap();
        app.execute_command("xrefs");
        assert_eq!(app.focus, Focus::Xrefs);
        assert_eq!(app.xref_at(), address);
        app.open(0x100b, true);
        app.back();
        assert_eq!(app.xref_at(), address);
    }

    #[test]
    fn catalog_commands_share_queries_filter_and_navigate() {
        let mut app = two_functions();
        app.an.imports.insert(0x100b, "test!ReadPacket".into());
        let expected =
            crate::api::symbols::imports_in(&app.an, &crate::api::symbols::SymbolQuery::default());
        app.execute_command("imports");
        let browser = app.browser.as_ref().unwrap();
        assert_eq!(browser.rows.len(), expected.len());
        assert_eq!(browser.rows[0].address, expected[0].address);
        app.set_filter("READPACKET".into());
        assert_eq!(app.browser.as_ref().unwrap().visible.len(), 1);
        app.open_browser_selection();
        assert_eq!(app.cur, Some(0x100b));
        app.execute_command("functions");
        assert!(app.browser.is_none());
        app.strings.insert(
            0x1000,
            Located {
                off: 0x1000,
                text: "packet header".into(),
                wide: false,
                len: 13,
            },
        );
        app.execute_command("strings");
        assert!(rendered(&mut app, 110, 30).contains("packet header"));
        let browser = app.browser.as_ref().unwrap();
        assert_eq!(
            browser.rows[0].file_offset,
            Some(crate::address::FileOffset(0x1000))
        );
        app.set_filter("not present".into());
        app.step(1);
        assert!(app.browser.as_ref().unwrap().visible.is_empty());
        app.open_browser_selection();
        assert!(app.status.contains("no catalog row"));
    }

    #[test]
    fn bookmark_commands_keep_user_notes_and_navigate() {
        let mut app = two_functions();
        app.open(0x100b, false);
        app.focus = Focus::Listing;
        app.execute_command("comment review caller");
        app.execute_command("bookmark");
        assert!(app.db.bookmarks.contains(&0x100b));
        app.open(0x1000, true);
        app.execute_command("bookmarks");
        assert_eq!(app.browser.as_ref().unwrap().visible.len(), 1);
        app.open_browser_selection();
        assert_eq!(app.cur, Some(0x100b));
        app.execute_command("bookmark");
        assert!(app.db.bookmarks.is_empty());
        assert_eq!(app.db.notes.get(&0x100b).unwrap(), "review caller");
    }

    #[test]
    fn section_catalog_matches_shared_query_and_opens_code() {
        let mut app = two_functions();
        let sections = crate::api::binary_summary::sections(&app.bin);
        app.execute_command("sections");
        let browser = app.browser.as_ref().unwrap();
        assert_eq!(browser.rows.len(), sections.len());
        assert_eq!(browser.rows[0].address, sections[0].static_address);
        assert_eq!(browser.rows[0].file_offset, Some(sections[0].file_offset));
        app.open_browser_selection();
        assert_eq!(app.cur, Some(0x1000));
    }

    #[test]
    fn shared_selector_keeps_interior_addresses_and_prefers_symbols() {
        let mut app = two_functions();
        app.an.names.insert(0x100b, "1000".into());
        let address = crate::api::navigation::resolve_address_in(&app.an, "1000").unwrap();
        assert_eq!(address.get(), 0x100b);
        app.execute_command("goto 0x1001");
        assert_eq!(
            crate::api::navigation::resolve_address_in(&app.an, "0x1001")
                .unwrap()
                .get(),
            0x1001
        );
        assert!(
            crate::api::navigation::resolve_address_in(&app.an, "184467440737095516160").is_err()
        );
        assert!(crate::api::navigation::resolve_address_in(&app.an, "0x0x1000").is_err());
    }

    #[test]
    fn failed_jump_preserves_forward_history() {
        let mut app = two_functions();
        app.open(0x100b, true);
        app.back();
        let future = app.future.clone();
        app.open(0xdeadbeef, true);
        assert_eq!(app.future, future);
        app.forward();
        assert_eq!(app.cur, Some(0x100b));
    }

    #[test]
    fn adaptive_panes_share_hit_testing_and_keyboard_controls() {
        use ratatui::layout::Rect;
        let mut app = two_functions();
        assert_eq!(
            app.panes(Rect::new(0, 0, 160, 40)).references.width,
            0,
            "an empty unfocused reference pane should not steal width"
        );
        app.focus = Focus::Xrefs;
        for (width, height) in [(100, 30), (160, 40)] {
            app.dims = (width, height);
            let panes = app.panes(Rect::new(0, 0, width, height));
            assert_eq!(
                app.pane_at(panes.listing.x + 1, panes.listing.y + 1)
                    .unwrap()
                    .0,
                Focus::Listing
            );
            assert_eq!(
                app.pane_at(panes.references.x + 1, panes.references.y + 1)
                    .unwrap()
                    .0,
                Focus::Xrefs
            );
            if width >= 132 {
                assert!(panes.references.x > panes.listing.x);
                assert_eq!(panes.references.y, panes.listing.y);
            } else {
                assert!(panes.references.y > panes.listing.y);
            }
            assert!(app.pane_at(width, height).is_none());
            assert!(app.pane_at(0, 0).is_none());
        }
        app.focus = Focus::Functions;
        app.execute_command("focus functions");
        let before = app.pane_settings.left_width;
        app.execute_command("widen");
        assert_eq!(app.pane_settings.left_width, before + 4);
        app.execute_command("close");
        assert_eq!(app.focus, Focus::Listing);
        assert_eq!(app.panes(Rect::new(0, 0, 160, 40)).functions.width, 0);
        app.execute_command("focus functions");
        assert!(app.panes(Rect::new(0, 0, 160, 40)).functions.width > 0);
        app.execute_command("focus references");
        app.execute_command("close");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(
            app.focus,
            Focus::Listing,
            "Tab skips both closed side panes"
        );
        app.execute_command("focus references");
        app.execute_command("narrow");
        assert_eq!(app.pane_settings.reference_width, 28);
        app.execute_command("focus listing");
        app.pane_settings.functions = true;
        app.pane_settings.references = true;
        let left_before = app.pane_settings.left_width;
        app.on_key(KeyEvent::new(KeyCode::Char('+'), KeyModifiers::NONE));
        assert_eq!(
            app.pane_settings.left_width,
            left_before - 4,
            "growing the listing takes width from a visible side pane"
        );
        app.on_key(KeyEvent::new(KeyCode::Char('-'), KeyModifiers::NONE));
        assert_eq!(app.pane_settings.left_width, left_before);
        app.on_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        let zoomed = app.panes(Rect::new(0, 0, 160, 40));
        assert_eq!(zoomed.listing.width, 160);
        assert_eq!(zoomed.functions.width, 0);
        assert_eq!(zoomed.references.width, 0);
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        let switched = app.panes(Rect::new(0, 0, 160, 40));
        assert_eq!(app.focus, Focus::Functions);
        assert_eq!(switched.functions.width, 160);
        app.execute_command("focus references");
        assert_eq!(app.panes(Rect::new(0, 0, 160, 40)).references.width, 160);
        app.on_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert!(app.pane_settings.zoom.is_none());
        app.execute_command("focus listing");
        app.execute_command("close");
        assert!(app.status.contains("listing stays open"));
    }

    #[test]
    fn catalog_jump_preserves_the_source_pseudocode_view_in_history() {
        let mut app = data_ref_app();
        app.toggle_pseudo();
        app.cursor = app.pseudo_lines.len() - 1;
        app.execute_command("sections");
        let origin = app.navigation_location().unwrap();
        app.browser.as_mut().unwrap().selection = 1;
        app.open_browser_selection();
        assert_eq!(app.cur, Some(0x101c));
        assert!(!app.pseudo);
        app.back();
        assert_eq!(app.navigation_location().unwrap(), origin);
    }

    #[test]
    fn adjacent_function_commands_are_ordered_bounded_and_reversible() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.execute_command("previous");
        assert_eq!(app.cur, Some(0x1000));
        assert!(app.history.is_empty());
        assert!(app.status.contains("no previous"));
        app.execute_command("next");
        assert_eq!(app.cur, Some(0x100b));
        let history_len = app.history.len();
        app.execute_command("next");
        assert_eq!(app.history.len(), history_len);
        assert!(app.status.contains("no next"));
        app.execute_command("previous");
        assert_eq!(app.cur, Some(0x1000));
        app.back();
        assert_eq!(app.cur, Some(0x100b));
        assert_eq!(
            crate::api::navigation::adjacent_function(
                &app.an,
                crate::address::StaticVa(0x1001),
                true
            ),
            Some(crate::address::StaticVa(0x100b))
        );
    }

    #[test]
    fn history_catalog_filters_and_restores_saved_view_not_just_address() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.focus = Focus::Listing;
        app.toggle_pseudo();
        app.cursor = app.pseudo_lines.len() - 1;
        let origin = app.navigation_location().unwrap();
        app.open(0x100b, true);
        app.execute_command("history");
        let browser = app.browser.as_mut().unwrap();
        assert_eq!(browser.rows.len(), 1);
        browser.filter("PAST PSEUDOCODE".into());
        assert_eq!(browser.visible.len(), 1);
        app.open_browser_selection();
        assert_eq!(app.navigation_location().unwrap(), origin);
        app.back();
        assert_eq!(app.cur, Some(0x100b));
        app.execute_command("history");
        assert!(app
            .browser
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .any(|row| row.detail.starts_with("FORWARD")));
        app.browser
            .as_mut()
            .unwrap()
            .filter("does not exist".into());
        app.open_browser_selection();
        assert!(app.status.contains("no catalog row"));
    }

    #[test]
    fn view_switching_preserves_independent_positions_through_history() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.cursor = app.lines.len() - 1;
        let assembly_cursor = app.cursor;
        app.toggle_pseudo();
        app.cursor = app.pseudo_lines.len() - 1;
        let pseudo_cursor = app.cursor;
        app.toggle_pseudo();
        assert_eq!(app.cursor, assembly_cursor);
        app.toggle_pseudo();
        assert_eq!(app.cursor, pseudo_cursor);
        app.open(0x100b, true);
        assert_eq!(
            app.cursor, 0,
            "new function has independent pseudocode position"
        );
        app.back();
        assert_eq!(app.cursor, pseudo_cursor);
        app.toggle_pseudo();
        assert_eq!(app.cursor, assembly_cursor);
        app.toggle_graph();
        app.toggle_pseudo();
        assert_eq!(app.cursor, pseudo_cursor);
    }

    #[test]
    fn graph_switching_correlates_the_selected_basic_block() {
        // test eax,eax; je 1005; ret; ret
        let mut app = app_with(&[0x85, 0xc0, 0x74, 0x01, 0xc3, 0xc3], 0x1000);
        app.open(0x1005, false);
        app.toggle_graph();
        assert_eq!(
            app.current_function().unwrap().blocks[app.cursor].start,
            0x1005
        );
        app.cursor = app
            .current_function()
            .unwrap()
            .blocks
            .iter()
            .position(|block| block.start == 0x1004)
            .unwrap();
        app.toggle_graph();
        assert!(!app.graph);
        assert_eq!(app.lines[app.cursor].addr(), 0x1004);
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
    fn call_queries_keep_sites_and_do_not_promote_branches_or_data() {
        use crate::address::StaticVa;
        use crate::analysis::engine::{Ref, Xref, XrefKind};
        use crate::api::references::{query_in, ReferenceView};
        let mut app = two_functions();
        // The call target also appears in a non-call operand. It must not be
        // promoted merely because the function has a real call to this target.
        app.an.xrefs_from.entry(0x1005).or_default().extend([
            Ref {
                to: 0x100b,
                kind: XrefKind::Branch,
            },
            Ref {
                to: 0x100b,
                kind: XrefKind::Data,
            },
        ]);
        app.an.xrefs_to.entry(0x100b).or_default().extend([
            Xref {
                from: 0x1005,
                kind: XrefKind::Branch,
            },
            Xref {
                from: 0x1005,
                kind: XrefKind::Data,
            },
        ]);
        let calls = query_in(&app.an, StaticVa(0x1000), ReferenceView::Callees);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].source, StaticVa(0x1000));
        assert_eq!(calls[0].target, StaticVa(0x100b));
        assert_eq!(calls[0].kind, XrefKind::Call);
        app.open(0x1000, false);
        app.lines.clear(); // Call results must not depend on rendered listing rows.
        app.execute_command("callees");
        assert_eq!(app.xref_rows()[0].site, calls[0].source.get());
        app.open(0x100b, false);
        app.execute_command("callers");
        assert_eq!(app.refview, RefView::Callers);
        assert_eq!(app.xref_rows().len(), 1);
        assert_eq!(app.xref_rows()[0].jump, 0x1000);
        assert_eq!(
            query_in(&app.an, StaticVa(0x100b), ReferenceView::Xrefs).len(),
            3
        );
        // Recovered tail-call jumps remain jumps, not ordinary calls.
        app.an.xrefs_from.get_mut(&0x1000).unwrap()[0].kind = XrefKind::Jump;
        app.an.xrefs_to.get_mut(&0x100b).unwrap()[0].kind = XrefKind::Jump;
        assert_eq!(
            query_in(&app.an, StaticVa(0x1000), ReferenceView::Callees)[0].kind,
            XrefKind::Jump
        );
        assert_eq!(
            query_in(&app.an, StaticVa(0x100b), ReferenceView::Callers)[0].kind,
            XrefKind::Jump
        );
        assert!(query_in(&app.an, StaticVa(0xffff), ReferenceView::Callees).is_empty());
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
    fn annotation_clearing_preserves_other_field_after_reload() {
        let root =
            std::env::temp_dir().join(format!("knife-tui-annotation-clear-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        for clear_name in [true, false] {
            let path = root.join(if clear_name { "name.json" } else { "note.json" });
            let mut app = two_functions();
            app.db = Db::load("annotation-test", "fixture", path.to_str()).unwrap();
            app.open(0x100b, false);
            app.commit(Ask::Name, 0x100b, "parse_header".into());
            app.commit(Ask::Note, 0x100b, "check the length".into());

            // Repeat the clear: an absent field must not erase its sibling either.
            for _ in 0..2 {
                app.commit(
                    if clear_name { Ask::Name } else { Ask::Note },
                    0x100b,
                    String::new(),
                );
                let saved = Db::load("annotation-test", "fixture", path.to_str()).unwrap();
                let expected_name = if clear_name {
                    None
                } else {
                    Some("parse_header")
                };
                let expected_note = if clear_name {
                    Some("check the length")
                } else {
                    None
                };
                assert_eq!(app.db.names.get(&0x100b).map(String::as_str), expected_name);
                assert_eq!(app.db.notes.get(&0x100b).map(String::as_str), expected_note);
                assert_eq!(saved.names.get(&0x100b).map(String::as_str), expected_name);
                assert_eq!(saved.notes.get(&0x100b).map(String::as_str), expected_note);
                assert_eq!(app.an.label(0x100b), expected_name.unwrap_or("sub_100b"));
            }
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
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

    #[test]
    fn reverse_focus_cycles_only_visible_panes_without_navigation() {
        for functions in [false, true] {
            for references in [false, true] {
                let mut app = two_functions();
                app.pane_settings.functions = functions;
                app.pane_settings.references = references;
                if references {
                    app.refview = RefView::From;
                    assert!(!app.xref_rows().is_empty());
                }
                let current = app.cur;
                let mut visible = vec![Focus::Listing];
                if functions {
                    visible.push(Focus::Functions);
                }
                if references {
                    visible.push(Focus::Xrefs);
                }
                for focus in &visible {
                    app.focus = *focus;
                    app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
                    assert!(visible.contains(&app.focus));
                    app.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
                    assert_eq!(app.focus, *focus);
                    app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT));
                    assert!(visible.contains(&app.focus));
                    app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
                    assert_eq!(app.focus, *focus);
                    assert_eq!(app.cur, current);
                }
            }
        }
    }

    /// Draw the main interface into an off-screen buffer for render assertions.
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
        // Empty secondary panes collapse during normal work, but explicitly
        // focusing one must still make it available and render it.
        app.focus = Focus::Xrefs;
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("functions"), "the function list is drawn");
        assert!(out.contains("entry"), "and lists what was recovered");
        assert!(out.contains("xrefs"), "the xref pane is drawn");
        assert!(
            out.contains(": commands"),
            "command mode stays discoverable"
        );
        assert!(out.contains("? help"), "help stays discoverable");
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
            trail: Vec::new(),
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
        app.help_scroll = render::help_max_scroll(110, 30);
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
    fn help_scrolls_in_a_short_terminal_without_moving_the_workspace() {
        let mut app = two_functions();
        app.dims = (40, 10);
        let before = app.cur;
        app.on_key(KeyEvent::from(KeyCode::Char('?')));
        let first = rendered(&mut app, 40, 10);
        assert!(first.contains("keys"));
        assert!(first.contains("Esc/? close"));
        app.on_key(KeyEvent::from(KeyCode::PageDown));
        assert_eq!(app.help_scroll, render::help_page_size(40, 10));
        app.on_key(KeyEvent::from(KeyCode::End));
        assert_eq!(app.help_scroll, render::help_max_scroll(40, 10));
        let last = rendered(&mut app, 40, 10);
        assert_ne!(first, last);
        app.dims = (80, 24);
        app.on_key(KeyEvent::from(KeyCode::Down));
        assert!(app.help_scroll <= render::help_max_scroll(80, 24));
        app.dims = (40, 10);
        app.on_key(KeyEvent::from(KeyCode::Home));
        assert_eq!(app.help_scroll, 0);
        app.on_mouse(mouse(MouseEventKind::ScrollDown, 2, 2));
        assert_eq!(app.help_scroll, 1);
        app.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(!app.help);
        assert!(!app.quit);
        assert_eq!(app.cur, before);
    }

    #[test]
    fn large_lists_render_the_selected_window_and_mouse_uses_that_window() {
        let mut app = two_functions();
        app.dims = (100, 20);
        app.an.functions = (0..50_000)
            .map(|index| engine::Function {
                addr: 0x1000 + index,
                name: format!("fn_{index:05}"),
                blocks: Vec::new(),
                size: 1,
                incoming: 0,
                calls: Vec::new(),
                named: false,
                tables: Vec::new(),
            })
            .collect();
        app.order = (0..50_000).collect();
        app.sel = 49_999;
        app.focus = Focus::Functions;
        let output = rendered(&mut app, 100, 20);
        assert!(output.contains("fn_49999"));
        assert!(!output.contains("fn_00000"));
        let panes = app.panes(ratatui::layout::Rect::new(0, 0, 100, 20));
        let start = render::viewport_start(49_999, 50_000, usize::from(panes.functions.height - 2));
        assert_eq!(
            app.pane_at(panes.functions.x + 1, panes.functions.y + 1),
            Some((Focus::Functions, start))
        );

        app.lines = (0..10_000)
            .map(|addr| Line::Data {
                addr,
                text: format!("row_{addr:05}"),
            })
            .collect();
        app.raw_file = true;
        app.cursor = 9_999;
        app.focus = Focus::Listing;
        let output = rendered(&mut app, 100, 20);
        assert!(output.contains("row_09999"));
        assert!(!output.contains("row_00000"));
        let panes = app.panes(ratatui::layout::Rect::new(0, 0, 100, 20));
        let start = render::viewport_start(9_999, 10_000, usize::from(panes.listing.height - 2));
        assert_eq!(
            app.pane_at(panes.listing.x + 1, panes.listing.y + 1),
            Some((Focus::Listing, start))
        );

        app.pseudo_lines = (0..10_000)
            .map(|index| crate::analysis::ir::Line {
                label: false,
                text: format!("pseudo_{index:05}"),
            })
            .collect();
        app.pseudo = true;
        app.raw_file = false;
        let output = rendered(&mut app, 100, 20);
        assert!(output.contains("pseudo_09999"));
        assert!(!output.contains("pseudo_00000"));
        assert_eq!(
            app.pane_at(panes.listing.x + 1, panes.listing.y + 1),
            Some((Focus::Listing, start))
        );

        app.split_clone();
        app.active_is_left = false;
        let output = rendered(&mut app, 100, 20);
        assert!(output.contains("pseudo_09999"));
        let panes = app.panes(ratatui::layout::Rect::new(0, 0, 100, 20));
        let start =
            render::viewport_start(9_999, 10_000, usize::from(panes.listing_right.height - 2));
        assert_eq!(
            app.pane_at(panes.listing_right.x + 1, panes.listing_right.y + 1),
            Some((Focus::Listing, start))
        );
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
        app.refview = RefView::From;
        assert!(!app.xref_rows().is_empty());
        assert_eq!(app.focus, Focus::Functions);
        for _ in 0..2 {
            app.on_key(KeyEvent::from(KeyCode::Tab));
        }
        assert_eq!(app.focus, Focus::Xrefs);
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Functions);
    }

    #[test]
    fn tab_skips_empty_references_but_explicit_focus_reveals_them() {
        let mut app = two_functions();
        assert!(app.xref_rows().is_empty());
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Listing);
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Functions);
        app.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.focus, Focus::Listing);
        app.execute_command("focus references");
        assert_eq!(app.focus, Focus::Xrefs);
        assert!(
            app.panes(ratatui::layout::Rect::new(0, 0, 160, 40))
                .references
                .width
                > 0
        );
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Functions);
        app.refview = RefView::From;
        app.on_key(KeyEvent::from(KeyCode::Tab));
        app.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Xrefs);
    }

    #[test]
    fn split_view_rejects_focus_on_hidden_references() {
        let mut app = two_functions();
        app.split_clone();
        let before = app.focus;
        app.execute_command("focus references");
        assert_eq!(app.focus, before);
        assert!(app.status.contains("hidden while split"));
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
    fn opening_data_from_pseudocode_clears_stale_view_and_back_restores_it() {
        let mut app = data_ref_app();
        app.toggle_pseudo();
        app.cursor = app.pseudo_lines.len() - 1;
        let origin = app.navigation_location().unwrap();
        app.open(0x101c, true);
        assert!(!app.pseudo);
        assert!(!app.graph);
        assert!(app.pseudo_lines.is_empty());
        assert!(!app.lines.is_empty());
        app.toggle_pseudo();
        assert!(!app.pseudo, "unsupported view leaves data visible");
        app.back();
        assert_eq!(app.navigation_location().unwrap(), origin);
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
        // Explicit focus temporarily reveals an empty adaptive pane. Check it
        // before moving focus away, which intentionally collapses it again.
        app.focus = Focus::Xrefs;
        app.on_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 100, 26));
        assert_eq!(app.focus, Focus::Xrefs);

        // A click in the left pane lands on the function list; with a single
        // recovered function the row index clamps to it.
        app.on_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 5, 4));
        assert_eq!(app.focus, Focus::Functions);
        assert_eq!(app.selected_addr(), Some(0x1000));
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
    fn loading_status_is_honest_and_renders_in_small_terminals() {
        use ratatui::{backend::TestBackend, Terminal};
        for (width, height) in [(100, 12), (12, 4)] {
            let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
            term.draw(|f| render::loading(f, "fixture.exe", 7)).unwrap();
            let text = term
                .backend()
                .buffer()
                .content()
                .iter()
                .map(|c| c.symbol())
                .collect::<String>();
            assert!(text.contains("KNIFE"));
            if width == 100 {
                assert!(text.contains("Elapsed: 7s"));
                assert!(text.contains("progress total unavailable"));
                assert!(text.contains("Ctrl+C: quit"));
                assert!(!text.contains("press any key"));
            }
        }
    }

    #[test]
    fn ready_workspace_handles_the_first_key_without_an_intro() {
        let mut app = two_functions();
        assert!(!app.splash, "a ready workspace does not play an intro");
        app.on_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(app.quit, "the first key is handled immediately");
        assert!(app.prompt.is_none());
    }

    #[test]
    fn goto_supports_explicit_address_modes() {
        let mut app = two_functions();
        // In the fixture the .text section is file-backed at its own address,
        // so a file offset and its static VA coincide.
        app.commit(Ask::Goto, 0, "off:0x100b".into());
        assert_eq!(app.cur, Some(0x100b), "file offset converts to a static VA");

        app.commit(Ask::Goto, 0, "va:0x1000".into());
        assert_eq!(app.cur, Some(0x1000), "va: pins a static VA");

        app.commit(Ask::Goto, 0, "file:0x1005".into());
        // file: is the same mode as off:; an interior address opens its
        // containing function, the same as a bare static VA would.
        assert_eq!(app.cur, Some(0x1000));

        app.commit(Ask::Goto, 0, "off:0x0".into());
        assert!(
            app.status.contains("not in a file-backed section"),
            "an offset outside every section says so: {}",
            app.status
        );
        assert_eq!(app.cur, Some(0x1000), "a failed goto moves nothing");

        app.commit(Ask::Goto, 0, "va:garbage".into());
        assert!(app.status.contains("bad static VA"), "{}", app.status);
    }

    #[test]
    fn error_messages_show_the_address_as_typed() {
        // Regression: miss errors used to add the image base a second time.
        let mut app = two_functions();
        app.commit(Ask::Goto, 0, "0xdead".into());
        assert!(
            app.status
                .contains("0xdead is not inside a recovered function"),
            "{}",
            app.status
        );
    }

    /// A parseable target whose only section holds data, not code.
    fn data_only_app() -> App {
        let bytes = b"\x7fELF\x02\x01\x01\0not code, just bytes".to_vec();
        let mut bin = Binary::stub(Format::Elf, Arch::X86_64);
        bin.entry = 0x1000;
        bin.sections = vec![Section {
            name: ".rodata".into(),
            vaddr: 0x1000,
            vsize: bytes.len() as u64,
            file_off: 0x1000,
            file_size: bytes.len() as u64,
            entropy: 0.0,
            read: true,
            write: false,
            exec: false,
        }];
        let mut padded = vec![0u8; 0x1000];
        padded.extend_from_slice(&bytes);
        let db = Db::default();
        let an = engine::analyze(&bin, &padded, 10_000, &db);
        assert!(an.functions.is_empty(), "the fixture recovers nothing");
        let sinks = ranked_sinks(&an, &bin, &padded);
        let strings = listing::string_map(&bin, &padded, engine::display_base(&bin));
        App::new(bin, padded, db, an, sinks, strings, None, "blob".into())
    }

    #[test]
    fn a_zero_function_target_opens_an_inspection_view() {
        let mut app = data_only_app();
        assert!(
            app.cur.is_some(),
            "the workspace opens on the first mapped bytes"
        );
        assert!(!app.lines.is_empty(), "the data view has rows to browse");
        assert!(
            app.status.contains("no functions recovered"),
            "the empty analysis is explained: {}",
            app.status
        );
        // Catalogs do not depend on recovered functions.
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("0 functions"), "the header stays honest");
    }

    #[test]
    fn a_zero_function_target_still_navigates_mapped_addresses() {
        let mut app = data_only_app();
        app.commit(Ask::Goto, 0, "0x1004".into());
        assert_eq!(app.cur, Some(0x1004), "goto opens the data at the address");
        app.commit(Ask::Goto, 0, "off:0x1004".into());
        assert_eq!(app.cur, Some(0x1004), "file offsets work the same way");
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Sinks, "view cycling still works");
    }

    /// Poll a reload to completion with a bound, so a stuck worker fails the
    /// test rather than hanging the suite.
    fn wait_for_reload(app: &mut App) {
        for _ in 0..1000 {
            app.poll_reload();
            if !app.is_reloading() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("the reload worker did not finish in five seconds");
    }

    fn temp_source(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("knife-tui-reload-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("target.elf"), dir.join("workspace.json"))
    }

    #[test]
    fn reload_swaps_the_target_and_preserves_the_desk_layout() {
        let (target, db_path) = temp_source("swap");
        std::fs::write(&target, crate::formats::fixture::elf_with_plt_call()).unwrap();

        let mut app = two_functions();
        app.pane_settings.left_width = 44;
        app.filter = "ent".into();
        app.refilter();
        app.open(0x1000, false);
        app.open(0x100b, true);
        assert_eq!(app.history.len(), 1, "the old image has navigation history");
        app.source = Some(TargetSource {
            path: target.clone(),
            db_path: Some(db_path.clone()),
        });

        app.reload();
        assert!(app.is_reloading(), "the worker is in flight");
        wait_for_reload(&mut app);

        assert!(
            !app.an.functions.is_empty(),
            "the disk fixture's functions arrived"
        );
        assert!(app.history.is_empty(), "old-image navigation is dropped");
        assert_eq!(
            app.pane_settings.left_width, 44,
            "pane layout survives a reload"
        );
        assert_eq!(app.filter, "ent", "the analyst's filter survives");
        assert!(
            app.status.contains("reloaded in"),
            "the swap is reported: {}",
            app.status
        );
        std::fs::remove_dir_all(target.parent().unwrap()).ok();
    }

    #[test]
    fn keys_are_inert_while_a_reload_is_in_flight() {
        let mut app = two_functions();
        app.open(0x1000, false);
        let (_tx, rx) = std::sync::mpsc::channel::<Result<ReloadOutcome>>();
        app.reloading = Some(rx);
        app.on_key(KeyEvent::from(KeyCode::Char('j')));
        assert_eq!(app.cur, Some(0x1000), "navigation does nothing mid-reload");
        assert!(!app.quit);
        app.on_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(app.quit, "leaving is still possible");
    }

    #[test]
    fn a_failed_reload_keeps_the_old_session() {
        let (target, db_path) = temp_source("missing");
        let mut app = two_functions();
        app.open(0x1000, false);
        app.open(0x100b, true);
        app.source = Some(TargetSource {
            path: target, // never written
            db_path: Some(db_path),
        });
        app.reload();
        wait_for_reload(&mut app);
        assert!(app.status.contains("reload failed"), "{}", app.status);
        assert_eq!(
            app.cur,
            Some(0x100b),
            "the old session is untouched by a failed reload"
        );
        assert_eq!(app.history.len(), 1, "history survives too");
    }

    #[test]
    fn reload_without_an_on_disk_source_reports_it() {
        let mut app = two_functions();
        app.reload();
        assert!(!app.is_reloading());
        assert!(app.status.contains("no on-disk target"), "{}", app.status);
    }

    #[test]
    fn split_clones_the_pane_and_the_columns_stay_independent() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.split_clone();
        assert!(app.split);
        assert_eq!(app.other.cur, app.cur, "the clone starts at the same spot");

        app.open(0x100b, true);
        assert_eq!(app.cur, Some(0x100b), "the active pane roams");
        assert_eq!(app.other.cur, Some(0x1000), "the pinned pane stays put");
        assert_eq!(app.other.history.len(), 0, "its own stack is not shared");
        assert_eq!(app.history.len(), 1, "the active pane has its own stack");
    }

    #[test]
    fn tab_walks_both_columns_and_the_wrap_is_stable() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.split_clone();
        app.open(0x100b, true);
        assert_eq!(app.focus, Focus::Functions);

        let tab = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        app.on_key(tab);
        assert_eq!(app.focus, Focus::Listing);
        assert!(
            app.active_is_left,
            "functions hands over to the left column"
        );
        assert_eq!(app.cur, Some(0x100b));

        app.on_key(tab);
        assert!(app.split);
        assert!(!app.active_is_left, "the right column takes the input");
        assert_eq!(
            app.cur,
            Some(0x1000),
            "the columns swapped, not the content"
        );

        app.on_key(tab);
        assert_eq!(app.focus, Focus::Functions, "the cycle wraps to functions");
        assert_eq!(app.cur, Some(0x1000), "the right column is still active");

        app.on_key(tab);
        assert!(app.active_is_left, "and the left column comes back");
        assert_eq!(app.cur, Some(0x100b));
    }

    #[test]
    fn compare_pins_a_function_in_the_other_column() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.compare(Some("0x100b".into()));
        assert!(app.split);
        assert_eq!(app.cur, Some(0x1000), "the active pane is untouched");
        assert_eq!(app.other.cur, Some(0x100b));
        assert!(
            app.other
                .lines
                .iter()
                .any(|line| matches!(line, Line::Insn { addr: 0x100b, .. })),
            "the pinned column shows the requested function"
        );

        app.compare(Some("no_such_thing".into()));
        assert!(
            app.status.contains("no symbol or address"),
            "{}",
            app.status
        );
        assert_eq!(app.other.cur, Some(0x100b), "a failed pin changes nothing");
    }

    #[test]
    fn only_keeps_the_active_column() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.split_clone();
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert!(!app.active_is_left, "the right column is active");
        app.close_split();
        assert!(!app.split);
        assert_eq!(app.cur, Some(0x1000), "the active column's state survives");
        assert!(app.other.cur.is_none(), "the other column is gone");
    }

    #[test]
    fn references_are_guarded_while_split() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.split_clone();
        app.execute_command("xrefs");
        assert!(app.status.contains("hidden while split"), "{}", app.status);
        assert_ne!(app.focus, Focus::Xrefs);
        app.on_key(KeyEvent::from(KeyCode::Char('x')));
        assert!(app.status.contains("hidden while split"), "{}", app.status);
    }

    #[test]
    fn reload_collapses_the_split() {
        let (target, db_path) = temp_source("split");
        std::fs::write(&target, crate::formats::fixture::elf_with_plt_call()).unwrap();
        let mut app = two_functions();
        app.open(0x1000, false);
        app.split_clone();
        assert!(app.split);
        app.source = Some(TargetSource {
            path: target.clone(),
            db_path: Some(db_path.clone()),
        });
        app.reload();
        wait_for_reload(&mut app);
        assert!(!app.split, "the other column belonged to the old image");
        assert!(app.other.cur.is_none());
        std::fs::remove_dir_all(target.parent().unwrap()).ok();
    }

    #[test]
    fn the_split_view_renders_two_columns() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.compare(Some("0x100b".into()));
        let out = rendered(&mut app, 110, 30);
        assert!(out.contains("entry @ 0x1000"), "the left column is drawn");
        assert!(
            out.contains("sub_100b @ 0x100b"),
            "the pinned column is drawn"
        );
        assert!(
            !out.contains("xrefs to"),
            "the references pane is hidden while split"
        );
    }

    #[test]
    fn a_too_small_terminal_gets_a_notice_instead_of_fragments() {
        let mut app = two_functions();
        for (w, h) in [(10u16, 4u16), (20, 5), (23, 30), (60, 5)] {
            let out = rendered(&mut app, w, h);
            assert!(out.contains("too small"), "{w}x{h} shows the notice");
        }
        let out = rendered(&mut app, 110, 30);
        assert!(
            !out.contains("terminal too small"),
            "a normal terminal is untouched"
        );
    }
}
