//! The interactive view: a function list, a listing, and cross-references,
//! with your names and notes written straight through to the database.
//!
//! State and rendering are kept apart on purpose. Everything that decides what
//! happens lives in `App` and is driven by plain method calls, so the awkward
//! parts (navigation, filtering, the follow-and-return stack) can be tested
//! without a terminal; `render` only ever reads.

mod render;

use crate::analysis::engine::{self, Analysis};
use crate::db::Db;
use crate::listing::{self, Line};
use crate::model::Binary;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Functions,
    Listing,
}

/// What a prompt at the bottom of the screen is collecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask {
    Filter,
    Name,
    Note,
    Goto,
}

impl Ask {
    fn label(self) -> &'static str {
        match self {
            Ask::Filter => "filter",
            Ask::Name => "name",
            Ask::Note => "note",
            Ask::Goto => "goto",
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

    // ── the rest ──
    pub focus: Focus,
    pub prompt: Option<Prompt>,
    pub history: Vec<(u64, usize)>,
    pub status: String,
    pub help: bool,
    pub quit: bool,
}

impl App {
    pub fn new(bin: Binary, bytes: Vec<u8>, db: Db, an: Analysis, title: String) -> App {
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
            focus: Focus::Functions,
            prompt: None,
            history: Vec::new(),
            status: String::new(),
            help: false,
            quit: false,
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
    pub fn open(&mut self, addr: u64, push: bool) {
        // Following a call can land on an address inside a function rather than
        // at its head, so resolve to whatever actually contains it.
        let target = self
            .an
            .find_function(addr)
            .or_else(|| self.an.function_at(addr))
            .map(|f| f.addr);

        let Some(faddr) = target else {
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
        self.lines = listing::function(&self.an, f, &self.db, self.base);
        self.cur = Some(faddr);
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
        if self.lines.is_empty() {
            return;
        }
        let last = self.lines.len() - 1;
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
    }

    /// The address the cursor is on, which is what a name, note, or
    /// cross-reference lookup applies to.
    pub fn cursor_addr(&self) -> Option<u64> {
        match self.focus {
            Focus::Listing => self.lines.get(self.cursor).map(Line::addr),
            Focus::Functions => self.selected_addr(),
        }
    }

    /// Follow the call or branch under the cursor.
    pub fn follow(&mut self) {
        let Some(t) = self.lines.get(self.cursor).and_then(Line::target) else {
            self.status = "nothing to follow here".into();
            return;
        };
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
    }

    /// Cross-references to whatever is under the cursor.
    pub fn xrefs(&self) -> (u64, &[engine::Xref]) {
        let at = self.cursor_addr().or(self.cur).unwrap_or(0);
        (
            at,
            self.an.xrefs_to.get(&at).map(Vec::as_slice).unwrap_or(&[]),
        )
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
                self.lines = listing::function(&self.an, f, &self.db, self.base);
                self.cursor = self.cursor.min(self.lines.len().saturating_sub(1));
            }
        }
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
                    Focus::Listing => Focus::Functions,
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::PageDown => self.step(page),
            KeyCode::PageUp => self.step(-page),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Enter => match self.focus {
                Focus::Functions => {
                    if let Some(a) = self.selected_addr() {
                        self.open(a, true);
                        self.focus = Focus::Listing;
                    }
                }
                Focus::Listing => self.follow(),
            },
            KeyCode::Backspace => self.back(),
            KeyCode::Char('/') => self.ask(Ask::Filter),
            KeyCode::Char('g') => self.ask(Ask::Goto),
            KeyCode::Char('n') => self.ask(Ask::Name),
            KeyCode::Char('c') => self.ask(Ask::Note),
            KeyCode::Char('r') => {
                self.reanalyze();
                self.status = "re-analysed".into();
            }
            _ => {}
        }
    }

    fn step(&mut self, delta: isize) {
        match self.focus {
            Focus::Functions => self.move_sel(delta),
            Focus::Listing => self.move_cursor(delta),
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
        };
        self.prompt = Some(Prompt { ask, input, at });
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
    let res = loop {
        if let Err(e) = term.draw(|f| render::draw(f, &app)) {
            break Err(e.into());
        }
        match event::read() {
            Ok(Event::Key(k)) => app.on_key(k),
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
        if app.quit {
            break Ok(());
        }
    };
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
}
