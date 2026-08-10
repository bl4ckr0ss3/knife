//! A native windowed view, in the spirit of a decompiler workbench: the
//! function list on the left, the disassembly and the decompiler in tabs at the
//! centre, cross-references below. It reuses the same engine, listing, and
//! decompiler the command line and the TUI do; only the presentation is new.
//!
//! Built on egui/eframe, which is pure Rust, so the GUI adds no C toolchain and
//! stays behind the `gui` feature to keep the default build lean.

use crate::analysis::engine::{self, Analysis, XrefKind};
use crate::analysis::ir;
use crate::analysis::strings::Located;
use crate::db::Db;
use crate::listing::{self, Annot, Line};
use crate::model::Binary;
use eframe::egui;
use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontFamily, FontId, RichText, Sense};
use std::collections::BTreeMap;

// ── palette (the same one the reports and the TUI use) ──
const RED: Color32 = Color32::from_rgb(0xe0, 0x55, 0x55);
const MUTED: Color32 = Color32::from_rgb(0x9b, 0x94, 0xae);
const FAINT: Color32 = Color32::from_rgb(0x79, 0x72, 0x8f);
const MINT: Color32 = Color32::from_rgb(0x7f, 0xd4, 0xc1);
const AMBER: Color32 = Color32::from_rgb(0xe0, 0xa8, 0x78);
const INK: Color32 = Color32::from_rgb(0xd7, 0xd3, 0xde);
const BG: Color32 = Color32::from_rgb(0x0d, 0x0d, 0x10);
const SURFACE: Color32 = Color32::from_rgb(0x15, 0x15, 0x1a);
const SEL: Color32 = Color32::from_rgb(0x2a, 0x26, 0x3a);

const MONO: f32 = 13.0;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Disasm,
    Decompiler,
}

pub struct GuiApp {
    bin: Binary,
    bytes: Vec<u8>,
    db: Db,
    an: Analysis,
    base: u64,
    strings: BTreeMap<u64, Located>,

    order: Vec<usize>,
    sel: usize,
    filter: String,

    cur: Option<u64>,
    lines: Vec<Line>,
    pseudo: Vec<ir::Line>,
    cursor: usize,
    tab: Tab,

    goto: String,
    status: String,
    // Set when a click asks to navigate; applied after the frame so the list
    // being drawn is not mutated mid-iteration.
    pending: Option<u64>,
}

impl GuiApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        bin: Binary,
        bytes: Vec<u8>,
        db: Db,
        an: Analysis,
    ) -> GuiApp {
        install_style(&cc.egui_ctx);
        let base = engine::display_base(&bin);
        let strings = listing::string_map(&bin, &bytes, base);
        let mut app = GuiApp {
            bin,
            bytes,
            db,
            an,
            base,
            strings,
            order: Vec::new(),
            sel: 0,
            filter: String::new(),
            cur: None,
            lines: Vec::new(),
            pseudo: Vec::new(),
            cursor: 0,
            tab: Tab::Disasm,
            goto: String::new(),
            status: String::new(),
            pending: None,
        };
        app.refilter();
        if let Some(&i) = app.order.first() {
            let a = app.an.functions[i].addr;
            app.open(a);
        }
        app
    }

    fn refilter(&mut self) {
        let keep = self.cur;
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

    /// Show whatever is at `addr`: a recovered function as code, otherwise a
    /// data dump.
    fn open(&mut self, addr: u64) {
        let target = self
            .an
            .find_function(addr)
            .or_else(|| self.an.function_at(addr))
            .map(|f| f.addr);

        match target {
            Some(faddr) => {
                let f = self.an.find_function(faddr).expect("resolved");
                self.lines = listing::function(&self.an, f, &self.db, self.base, &self.strings);
                self.pseudo = ir::decompile(&self.an, &self.bin, f);
                self.cur = Some(faddr);
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
                self.status.clear();
            }
            None if engine::va_to_off(&self.bin, self.base, addr).is_some() => {
                self.lines = listing::data_view(&self.bin, self.base, &self.bytes, addr);
                self.pseudo.clear();
                self.cur = Some(addr);
                self.cursor = 0;
            }
            None => {
                self.status = format!("0x{addr:x} is not inside a recovered function");
            }
        }
    }

    /// Follow the call/branch/data reference on the current line.
    fn follow(&mut self) {
        if let Some(Line::Insn {
            target: Some(t), ..
        }) = self.lines.get(self.cursor)
        {
            self.pending = Some(*t);
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _f: &mut eframe::Frame) {
        self.top_bar(ctx);
        self.function_panel(ctx);
        self.xref_panel(ctx);
        self.code_panel(ctx);

        if let Some(a) = self.pending.take() {
            self.open(a);
        }
    }
}

impl GuiApp {
    fn top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("bar")
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(8.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("▌").color(RED).strong());
                    ui.label(RichText::new(&self.bin.path).color(RED).strong());
                    let named = self.an.functions.iter().filter(|f| f.named).count();
                    ui.label(
                        RichText::new(format!(
                            "{} · {} · {} functions, {} named",
                            self.bin.format.label(),
                            self.bin.arch.label(),
                            self.an.functions.len(),
                            named
                        ))
                        .color(FAINT),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("go").clicked() {
                            self.do_goto();
                        }
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut self.goto)
                                .desired_width(150.0)
                                .hint_text("goto addr / symbol"),
                        );
                        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            self.do_goto();
                        }
                    });
                });
            });
    }

    fn do_goto(&mut self) {
        let t = self.goto.trim().to_string();
        if t.is_empty() {
            return;
        }
        let parsed = t
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok());
        if let Some(a) = parsed {
            self.pending = Some(a);
        } else {
            match self.an.resolve(&t, None).first() {
                Some(&a) => self.pending = Some(a),
                None => self.status = format!("no symbol or address '{t}'"),
            }
        }
        self.goto.clear();
    }

    fn function_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("functions")
            .resizable(true)
            .default_width(320.0)
            .frame(egui::Frame::new().fill(BG).inner_margin(6.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("functions ({})", self.order.len())).color(RED));
                });
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.filter)
                            .desired_width(f32::INFINITY)
                            .hint_text("/ filter"),
                    )
                    .changed()
                {
                    self.refilter();
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let order = self.order.clone();
                        for &i in &order {
                            let fun = &self.an.functions[i];
                            let here = self.cur == Some(fun.addr);
                            let mut job = LayoutJob::default();
                            seg(&mut job, format!("{:>10x} ", fun.addr + self.base), FAINT);
                            seg(
                                &mut job,
                                trunc(&fun.name, 22),
                                if fun.named { MINT } else { MUTED },
                            );
                            seg(&mut job, format!(" {:>3}", fun.incoming), FAINT);
                            if row_widget(ui, job, here).clicked() {
                                self.pending = Some(fun.addr);
                            }
                        }
                    });
            });
    }

    fn xref_panel(&mut self, ctx: &egui::Context) {
        let at = self.cur.unwrap_or(0);
        let refs: Vec<engine::Xref> = self.an.xrefs_to.get(&at).cloned().unwrap_or_default();
        egui::TopBottomPanel::bottom("xrefs")
            .resizable(true)
            .default_height(150.0)
            .frame(egui::Frame::new().fill(BG).inner_margin(6.0))
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("xrefs to 0x{:x} ({})", at + self.base, refs.len()))
                        .color(RED),
                );
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if refs.is_empty() {
                            ui.label(RichText::new("no references").color(FAINT));
                        }
                        for x in &refs {
                            let site = match self.an.function_at(x.from) {
                                Some(fun) => {
                                    let off = x.from.saturating_sub(fun.addr);
                                    if off == 0 {
                                        fun.name.clone()
                                    } else {
                                        format!("{}+0x{off:x}", fun.name)
                                    }
                                }
                                None => "-".into(),
                            };
                            let mut job = LayoutJob::default();
                            seg(&mut job, format!("{:>10x}  ", x.from + self.base), FAINT);
                            seg(
                                &mut job,
                                format!("{:<7}", x.kind.label()),
                                match x.kind {
                                    XrefKind::Call => MINT,
                                    XrefKind::Data => MUTED,
                                    _ => AMBER,
                                },
                            );
                            seg(&mut job, site, MUTED);
                            if row_widget(ui, job, false).clicked() {
                                self.pending = Some(x.from);
                            }
                        }
                    });
            });
    }

    fn code_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(BG).inner_margin(8.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let title = match self.cur {
                        Some(a) => format!("{} @ 0x{:x}", self.an.label(a), a + self.base),
                        None => "listing".into(),
                    };
                    ui.label(RichText::new(title).color(RED).strong());
                    ui.separator();
                    ui.selectable_value(&mut self.tab, Tab::Disasm, "disassembly");
                    ui.selectable_value(&mut self.tab, Tab::Decompiler, "decompiler");
                });
                ui.separator();
                if !self.status.is_empty() {
                    ui.label(RichText::new(&self.status).color(AMBER));
                }
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.tab {
                        Tab::Disasm => self.draw_disasm(ui),
                        Tab::Decompiler => self.draw_pseudo(ui),
                    });
            });
    }

    fn draw_disasm(&mut self, ui: &mut egui::Ui) {
        for idx in 0..self.lines.len() {
            let job = disasm_job(&self.lines[idx], self.base);
            let selected = idx == self.cursor;
            let r = row_widget(ui, job, selected);
            if r.clicked() {
                self.cursor = idx;
            }
            if r.double_clicked() {
                self.cursor = idx;
                self.follow();
            }
        }
    }

    fn draw_pseudo(&mut self, ui: &mut egui::Ui) {
        if self.pseudo.is_empty() {
            ui.label(RichText::new("no pseudocode for this view").color(FAINT));
            return;
        }
        for l in &self.pseudo {
            let job = pseudo_job(l);
            row_widget(ui, job, false);
        }
    }
}

// ── rendering helpers ──

fn seg(job: &mut LayoutJob, text: impl Into<String>, color: Color32) {
    job.append(
        &text.into(),
        0.0,
        TextFormat {
            font_id: FontId::new(MONO, FontFamily::Monospace),
            color,
            ..Default::default()
        },
    );
}

/// A full-width clickable row that highlights when selected.
fn row_widget(ui: &mut egui::Ui, job: LayoutJob, selected: bool) -> egui::Response {
    let fill = if selected { SEL } else { Color32::TRANSPARENT };
    egui::Frame::new()
        .fill(fill)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(job).sense(Sense::click()).wrap())
        })
        .inner
}

fn disasm_job(line: &Line, base: u64) -> LayoutJob {
    let mut job = LayoutJob::default();
    match line {
        Line::Label { text, .. } => seg(&mut job, format!("  {text}:"), AMBER),
        Line::Data { addr, text } => {
            seg(&mut job, format!("{:012x}  ", addr + base), FAINT);
            seg(&mut job, text.clone(), MUTED);
        }
        Line::Insn {
            addr,
            mnemonic,
            operands,
            annot,
            ..
        } => {
            seg(&mut job, format!("{:012x}  ", addr + base), FAINT);
            seg(&mut job, format!("{mnemonic:<7} "), RED);
            seg(&mut job, operands.clone(), MUTED);
            if let Some(a) = annot {
                let (t, c) = match a {
                    Annot::Note(t) => (t.clone(), AMBER),
                    Annot::Symbol(t) => (t.clone(), MINT),
                    Annot::Local(t) => (t.clone(), FAINT),
                    Annot::Text(t) => (format!("\"{t}\""), AMBER),
                };
                seg(&mut job, format!("  ; {t}"), c);
            }
        }
    }
    job
}

fn pseudo_job(l: &ir::Line) -> LayoutJob {
    const KW: &[&str] = &[
        "if", "else", "while", "switch", "case", "break", "continue", "goto", "return", "do", "for",
    ];
    let mut job = LayoutJob::default();
    if l.label {
        let c = if l.text.trim_end().ends_with(':') {
            AMBER
        } else {
            RED
        };
        seg(&mut job, l.text.clone(), c);
        return job;
    }
    let mut buf = String::new();
    let mut word = false;
    let flush = |buf: &mut String, word: bool, job: &mut LayoutJob| {
        if buf.is_empty() {
            return;
        }
        let c = if word && KW.contains(&buf.as_str()) {
            RED
        } else {
            INK
        };
        seg(job, std::mem::take(buf), c);
    };
    for ch in l.text.chars() {
        let w = ch.is_alphanumeric() || ch == '_';
        if w != word {
            flush(&mut buf, word, &mut job);
            word = w;
        }
        buf.push(ch);
    }
    flush(&mut buf, word, &mut job);
    job
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}

fn install_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    for id in style.text_styles.values_mut() {
        id.family = FontFamily::Monospace;
    }
    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = SURFACE;
    v.extreme_bg_color = SURFACE;
    v.override_text_color = Some(INK);
    v.selection.bg_fill = SEL;
    v.selection.stroke.color = RED;
    v.hyperlink_color = RED;
    v.widgets.hovered.bg_stroke.color = RED;
    style.visuals = v;
    ctx.set_style(style);
}

/// Open the windowed view and run until the window is closed.
pub fn run(bin: Binary, bytes: Vec<u8>, db: Db, an: Analysis, title: String) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title(format!("knife — {title}")),
        ..Default::default()
    };
    eframe::run_native(
        "knife",
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc, bin, bytes, db, an)))),
    )
    .map_err(|e| anyhow::anyhow!("could not open the window: {e}"))
}
