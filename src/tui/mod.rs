//! The interactive view: a function list, a listing, and cross-references,
//! with your names and notes written straight through to the database.
//!
//! State and rendering are kept apart on purpose. Everything that decides what
//! happens lives in `App` and is driven by plain method calls, so the awkward
//! parts (navigation, filtering, the follow-and-return stack) can be tested
//! without a terminal; `render` only ever reads.

mod render;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Functions,
    Listing,
    Xrefs,
}

/// What the left pane is showing: the function list or the ranked sink sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftView {
    Functions,
    Sinks,
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

/// What a prompt at the bottom of the screen is collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    Filter,
    Name,
    Note,
    Goto,
    /// Text to find within the current listing.
    Search,
}

impl Ask {
    fn label(self) -> &'static str {
        match self {
            Ask::Filter => "filter",
            Ask::Name => "name",
            Ask::Note => "note",
            Ask::Goto => "goto",
            Ask::Search => "search",
        }
    }
}

pub struct Prompt {
    pub ask: Ask,
    pub input: String,
    /// The address a name or note will attach to.
    pub at: u64,
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

    // ── listing ──
    pub cur: Option<u64>,
    pub lines: Vec<Line>,
    pub cursor: usize,
    /// When set, the listing pane shows decompiled pseudocode for the current
    /// function instead of the disassembly.
    pub pseudo: bool,
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

    // ── in-listing search ──
    /// The last text searched for in the listing, so repeating advances.
    pub search: String,

    /// Whether the reference pane shows callers (to) or callees (from).
    pub refview: RefView,
}

impl App {
    pub fn new(bin: Binary, bytes: Vec<u8>, db: Db, an: Analysis, title: String) -> App {
        let base = engine::display_base(&bin);
        let strings = listing::string_map(&bin, &bytes, base);
        // The attack surface, computed once: the argument-provenance audit, most
        // severe first, then the reachable ones, then by address.
        let mut sinks = crate::analysis::audit::run(&an, &bin, &bytes);
        sinks.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.reachable.cmp(&a.reachable))
                .then(a.addr.cmp(&b.addr))
        });
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
            search: String::new(),
            refview: RefView::To,
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
        self.lines = listing::function(&self.an, f, &self.db, self.base, &self.strings);
        self.cur = Some(faddr);
        self.clamp_xsel();
        // Land on the requested address, not merely the top of the function.
        self.cursor = self
            .lines
            .iter()
            .position(|l| l.addr() == addr)
            .unwrap_or(0);
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
        if self.pseudo {
            self.pseudo_lines.len()
        } else {
            self.lines.len()
        }
    }

    /// Rebuild the decompiled lines for the current function.
    fn recompute_pseudo(&mut self) {
        self.pseudo_lines.clear();
        if let Some(addr) = self.cur {
            if let Some(f) = self.an.find_function(addr) {
                self.pseudo_lines =
                    crate::analysis::ir::decompile(&self.an, &self.bin, f, &self.strings);
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
        self.pseudo = !self.pseudo;
        self.cursor = 0;
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
        if self.pseudo {
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

    // ── sinks ──

    pub fn toggle_sinks(&mut self) {
        self.left = match self.left {
            LeftView::Functions => LeftView::Sinks,
            LeftView::Sinks => LeftView::Functions,
        };
        self.focus = Focus::Functions;
        if self.left == LeftView::Sinks && self.sinks.is_empty() {
            self.status = "no sinks found (audit is x86/x64 only)".into();
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

    /// The address the cursor is on, which is what a name, note, or
    /// cross-reference lookup applies to.
    pub fn cursor_addr(&self) -> Option<u64> {
        match self.focus {
            // A pseudocode line has no address of its own, so naming and noting
            // in that view apply to the function as a whole.
            Focus::Listing if self.pseudo => self.cur,
            Focus::Listing => self.lines.get(self.cursor).map(Line::addr),
            Focus::Functions => self.selected_addr(),
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

    fn commit(&mut self, ask: Ask, at: u64, text: String) {
        let stored = at.wrapping_sub(self.base);
        match ask {
            Ask::Filter => {
                self.filter = text;
                self.refilter();
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
                self.lines = listing::function(&self.an, f, &self.db, self.base, &self.strings);
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

    // ── input ──

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return; // Windows reports releases too; acting on both double-fires
        }

        if let Some(p) = &mut self.prompt {
            match key.code {
                KeyCode::Esc => self.prompt = None,
                KeyCode::Enter => {
                    let p = self.prompt.take().expect("checked above");
                    self.commit(p.ask, p.at, p.input);
                }
                KeyCode::Backspace => {
                    p.input.pop();
                    // A filter should react as it is typed.
                    if p.ask == Ask::Filter {
                        let text = p.input.clone();
                        self.filter = text;
                        self.refilter();
                    }
                }
                KeyCode::Char(c) => {
                    p.input.push(c);
                    if p.ask == Ask::Filter {
                        let text = p.input.clone();
                        self.filter = text;
                        self.refilter();
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
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::PageDown => self.step(page),
            KeyCode::PageUp => self.step(-page),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Enter => match self.focus {
                Focus::Functions => match self.left {
                    LeftView::Sinks => self.open_sink(),
                    LeftView::Functions => {
                        if let Some(a) = self.selected_addr() {
                            self.open(a, true);
                            self.focus = Focus::Listing;
                        }
                    }
                },
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
            KeyCode::Char('s') => self.toggle_sinks(),
            KeyCode::Char('x') => self.toggle_refs(),
            KeyCode::Char('d') => {
                self.toggle_pseudo();
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
            },
            Focus::Listing => self.move_cursor(delta),
            Focus::Xrefs => self.move_xsel(delta),
        }
    }

    fn ask(&mut self, ask: Ask) {
        let at = self.cursor_addr().unwrap_or(0);
        // Editing an existing value should start from it rather than blank.
        let stored = at.wrapping_sub(self.base);
        let input = match ask {
            Ask::Filter => self.filter.clone(),
            Ask::Name => self.db.names.get(&stored).cloned().unwrap_or_default(),
            Ask::Note => self.db.notes.get(&stored).cloned().unwrap_or_default(),
            Ask::Goto => String::new(),
            // Prefilled with the last search so pressing `/`↵ repeats it.
            Ask::Search => self.search.clone(),
        };
        self.prompt = Some(Prompt { ask, input, at });
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
        let fns_w = 34.min(w);
        let xrefs_h = 8u16.min(body_h);
        let left_len = match self.left {
            LeftView::Functions => self.order.len(),
            LeftView::Sinks => self.sinks.len(),
        };
        let (focus, list_len, pane_row) = if column < fns_w {
            (Focus::Functions, left_len, row)
        } else if row + xrefs_h < h.saturating_sub(1) {
            (Focus::Listing, self.listing_len(), row)
        } else {
            (
                Focus::Xrefs,
                self.xref_rows().len(),
                row - (h.saturating_sub(1) - xrefs_h),
            )
        };
        // row 0 of the pane is the border, row 1 the title; items start there.
        let idx = pane_row.saturating_sub(2) as usize;
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

fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim();
    t.strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .and_then(|h| u64::from_str_radix(h, 16).ok())
}

/// Run the interactive view until the user quits.
pub fn run(mut app: App) -> Result<()> {
    // `try_init` rather than `init`, so running this with output piped fails
    // with a sentence instead of a panic. It installs a panic hook that
    // restores the terminal, so a crash cannot leave the shell in raw mode.
    let mut term = ratatui::try_init()
        .map_err(|e| anyhow::anyhow!("cannot start the interactive view: {e}"))?;
    let _ = ratatui::crossterm::execute!(&mut stdout(), event::EnableMouseCapture);
    let res = loop {
        if let Ok(area) = term.size() {
            app.dims = (area.width, area.height);
        }
        if let Err(e) = term.draw(|f| render::draw(f, &app)) {
            break Err(e.into());
        }
        match event::read() {
            Ok(Event::Key(k)) => app.on_key(k),
            Ok(Event::Mouse(m)) => app.on_mouse(m),
            Ok(_) => {}
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
        App::new(bin, bytes, db, an, "t".into())
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
    fn the_left_pane_toggles_between_functions_and_sinks() {
        let mut app = two_functions();
        assert_eq!(app.left, LeftView::Functions);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Sinks);
        app.toggle_sinks();
        assert_eq!(app.left, LeftView::Functions);
        // With no sinks recovered, navigating them must not panic.
        app.left = LeftView::Sinks;
        app.move_ssel(1);
        app.move_ssel(-1);
        app.open_sink();
        assert_eq!(app.ssel, 0);
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
    fn rendered(app: &App, w: u16, h: u16) -> String {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
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
        let app = two_functions();
        let out = rendered(&app, 110, 30);
        assert!(out.contains("functions"), "the function list is drawn");
        assert!(out.contains("entry"), "and lists what was recovered");
        assert!(out.contains("xrefs"), "the xref pane is drawn");
        assert!(out.contains("open/follow"), "the key hints are drawn");
    }

    #[test]
    fn the_sinks_pane_renders() {
        let mut app = two_functions();
        app.toggle_sinks();
        let out = rendered(&app, 110, 30);
        assert!(out.contains("sinks"), "the sinks pane title is drawn");
    }

    #[test]
    fn the_pseudocode_view_renders() {
        let mut app = two_functions();
        app.open(0x1000, false);
        app.toggle_pseudo();
        let out = rendered(&app, 110, 30);
        assert!(out.contains("pseudocode"), "the pseudocode pane is drawn");
        assert!(out.contains("sub_"), "and shows a decompiled signature");
    }

    #[test]
    fn it_renders_in_a_very_small_terminal() {
        // Layout arithmetic that underflows shows up here as a panic.
        let app = two_functions();
        for (w, h) in [(20u16, 6u16), (40, 10), (1, 1), (200, 60)] {
            let _ = rendered(&app, w, h);
        }
    }

    #[test]
    fn the_help_overlay_and_prompt_render() {
        let mut app = two_functions();
        app.help = true;
        assert!(rendered(&app, 110, 30).contains("re-analyse"));

        app.help = false;
        app.prompt = Some(Prompt {
            ask: Ask::Name,
            input: "parse_header".into(),
            at: 0x1000,
        });
        let out = rendered(&app, 110, 30);
        assert!(out.contains("name:"), "the prompt shows what it wants");
        assert!(out.contains("parse_header"), "and what has been typed");
    }

    #[test]
    fn typing_in_a_prompt_edits_it_and_escape_abandons_it() {
        let mut app = two_functions();
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
        App::new(bin, bytes, db, an, "t".into())
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
}
