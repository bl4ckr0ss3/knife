//! Drawing. Reads `App` and never changes it.
//!
//! The palette is the same one the printed output uses, so the interactive view
//! and the reports look like the same tool.

use super::{App, Focus, LeftView, Line};
use crate::analysis::engine::XrefKind;
use crate::listing::Annot;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};
use ratatui::Frame;

fn accent() -> Color {
    Color::Rgb(0xe0, 0x55, 0x55)
}
fn muted() -> Color {
    Color::Rgb(0x9b, 0x94, 0xae)
}
fn faint() -> Color {
    Color::Rgb(0x79, 0x72, 0x8f)
}
fn mint() -> Color {
    Color::Rgb(0x7f, 0xd4, 0xc1)
}
fn amber() -> Color {
    Color::Rgb(0xe0, 0xa8, 0x78)
}

fn pane(title: &str, focused: bool) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { accent() } else { faint() }))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(if focused { accent() } else { faint() }),
        ))
}

pub fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(5),    // body
            Constraint::Length(1), // prompt / hints
        ])
        .split(f.area());

    header(f, rows[0], app);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(20)])
        .split(rows[1]);

    functions(f, cols[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(8)])
        .split(cols[1]);

    listing(f, right[0], app);
    xrefs(f, right[1], app);

    footer(f, rows[2], app);

    if app.help {
        help(f, f.area());
    }
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let named = app.an.functions.iter().filter(|x| x.named).count();
    let line = TLine::from(vec![
        Span::styled(
            format!(" {} ", app.title),
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "{} · {} · {} functions, {} named",
                app.bin.format.label(),
                app.bin.arch.label(),
                app.an.functions.len(),
                named
            ),
            Style::default().fg(faint()),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn functions(f: &mut Frame, area: Rect, app: &App) {
    if app.left == LeftView::Sinks {
        sinks(f, area, app);
        return;
    }
    let focused = app.focus == Focus::Functions;
    // The function containing whatever the listing shows is marked, so moving
    // through code keeps the left pane in step even after following calls.
    let current = app.cur;
    let items: Vec<ListItem> = app
        .order
        .iter()
        .map(|&i| {
            let fun = &app.an.functions[i];
            let here = current == Some(fun.addr);
            let mut spans = Vec::new();
            if here {
                spans.push(Span::styled("·", Style::default().fg(amber())));
            }
            spans.push(Span::styled(
                format!("{:>10x} ", fun.addr + app.an.display_base),
                Style::default().fg(faint()),
            ));
            spans.push(Span::styled(
                truncate(&fun.name, 16),
                Style::default().fg(if fun.named { mint() } else { muted() }),
            ));
            spans.push(Span::styled(
                format!(" {:>3}", fun.incoming),
                Style::default().fg(faint()),
            ));
            ListItem::new(TLine::from(spans))
        })
        .collect();

    let title = if app.filter.is_empty() {
        format!("functions ({})", app.order.len())
    } else {
        format!("functions ({}) /{}", app.order.len(), app.filter)
    };

    let mut state = ListState::default();
    if !app.order.is_empty() {
        state.select(Some(app.sel));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(Style::default().bg(Color::Rgb(0x2a, 0x26, 0x3a)))
            .highlight_symbol("›"),
        area,
        &mut state,
    );
}

/// The attack surface: ranked sink call sites, most severe first.
fn sinks(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Functions;
    let items: Vec<ListItem> = if app.sinks.is_empty() {
        vec![ListItem::new(TLine::from(Span::styled(
            " no sinks found",
            Style::default().fg(faint()),
        )))]
    } else {
        app.sinks
            .iter()
            .map(|s| {
                // 3 = looks exploitable, 2 = worth a look, 1 = context.
                let (mark, color) = match s.severity {
                    3 => ("!", accent()),
                    2 => ("=", amber()),
                    _ => ("·", muted()),
                };
                let where_ = s.func.as_deref().unwrap_or("-");
                ListItem::new(TLine::from(vec![
                    Span::styled(format!("{mark} "), Style::default().fg(color)),
                    Span::styled(
                        format!("{:<12} ", truncate(&s.api, 12)),
                        Style::default().fg(color),
                    ),
                    Span::styled(
                        format!("{:>10x} ", s.addr + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(truncate(where_, 14), Style::default().fg(muted())),
                ]))
            })
            .collect()
    };

    let title = format!("sinks ({})", app.sinks.len());
    let mut state = ListState::default();
    if !app.sinks.is_empty() {
        state.select(Some(app.ssel.min(app.sinks.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(Style::default().bg(Color::Rgb(0x2a, 0x26, 0x3a)))
            .highlight_symbol("›"),
        area,
        &mut state,
    );
}

fn listing(f: &mut Frame, area: Rect, app: &App) {
    if app.pseudo {
        pseudo(f, area, app);
        return;
    }
    let focused = app.focus == Focus::Listing;
    let title = match app.cur {
        Some(a) => format!(
            "{} @ 0x{:x}{}",
            app.an.label(a),
            a + app.an.display_base,
            position(app.cursor, app.lines.len())
        ),
        None => "listing".into(),
    };

    let items: Vec<ListItem> = app
        .lines
        .iter()
        .map(|l| match l {
            Line::Label { text, .. } => ListItem::new(TLine::from(Span::styled(
                format!("  {text}:"),
                Style::default().fg(amber()),
            ))),
            Line::Data { addr, text } => ListItem::new(TLine::from(vec![
                Span::styled(
                    format!("{:012x}  ", addr + app.an.display_base),
                    Style::default().fg(faint()),
                ),
                Span::styled(text.clone(), Style::default().fg(muted())),
            ])),
            Line::Insn {
                addr,
                mnemonic,
                operands,
                annot,
                ..
            } => {
                let mut spans = vec![
                    Span::styled(
                        format!("{:012x}  ", addr + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(format!("{mnemonic:<7} "), Style::default().fg(accent())),
                    Span::styled(operands.clone(), Style::default().fg(muted())),
                ];
                if let Some(a) = annot {
                    let (text, color) = match a {
                        // A note is the one annotation a person wrote, so it is
                        // the one that should catch the eye.
                        Annot::Note(t) => (t.clone(), amber()),
                        Annot::Symbol(t) => (t.clone(), mint()),
                        Annot::Local(t) => (t.clone(), faint()),
                        // A string literal is a quote, so it is drawn quoted.
                        Annot::Text(t) => (format!("\"{t}\""), amber()),
                    };
                    spans.push(Span::styled(
                        format!("  ; {text}"),
                        Style::default().fg(color),
                    ));
                }
                ListItem::new(TLine::from(spans))
            }
        })
        .collect();

    let mut state = ListState::default();
    if !app.lines.is_empty() {
        state.select(Some(app.cursor));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(Style::default().bg(Color::Rgb(0x2a, 0x26, 0x3a)))
            .highlight_symbol("›"),
        area,
        &mut state,
    );
}

/// Colour a line of pseudocode: keywords stand out, everything else is muted.
fn pseudo_spans(text: &str) -> Vec<Span<'static>> {
    const KW: &[&str] = &[
        "if", "else", "while", "switch", "case", "break", "continue", "goto", "return", "do", "for",
    ];
    let mut spans = Vec::new();
    let mut buf = String::new();
    let mut buf_word = false;
    let flush = |buf: &mut String, word: bool, spans: &mut Vec<Span<'static>>| {
        if buf.is_empty() {
            return;
        }
        let color = if word && KW.contains(&buf.as_str()) {
            accent()
        } else {
            muted()
        };
        spans.push(Span::styled(
            std::mem::take(buf),
            Style::default().fg(color),
        ));
    };
    for ch in text.chars() {
        let word = ch.is_alphanumeric() || ch == '_';
        if word != buf_word {
            flush(&mut buf, buf_word, &mut spans);
            buf_word = word;
        }
        buf.push(ch);
    }
    flush(&mut buf, buf_word, &mut spans);
    spans
}

fn pseudo(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Listing;
    let title = match app.cur {
        Some(a) => format!(
            "pseudocode · {} @ 0x{:x}{}",
            app.an.label(a),
            a + app.an.display_base,
            position(app.cursor, app.pseudo_lines.len())
        ),
        None => "pseudocode".into(),
    };

    let mut items: Vec<ListItem> = app
        .pseudo_lines
        .iter()
        .map(|l| {
            if l.label {
                // A jump label reads like one; the signature and braces are the
                // structure, so they take the accent.
                let color = if l.text.trim_end().ends_with(':') {
                    amber()
                } else {
                    accent()
                };
                ListItem::new(TLine::from(Span::styled(
                    l.text.clone(),
                    Style::default().fg(color),
                )))
            } else {
                ListItem::new(TLine::from(pseudo_spans(&l.text)))
            }
        })
        .collect();
    if items.is_empty() {
        items.push(ListItem::new(TLine::from(Span::styled(
            "  (no pseudocode for this view)",
            Style::default().fg(faint()),
        ))));
    }

    let mut state = ListState::default();
    if !app.pseudo_lines.is_empty() {
        state.select(Some(app.cursor.min(app.pseudo_lines.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(Style::default().bg(Color::Rgb(0x2a, 0x26, 0x3a)))
            .highlight_symbol("›"),
        area,
        &mut state,
    );
}

fn xrefs(f: &mut Frame, area: Rect, app: &App) {
    let (at, refs) = app.xrefs();
    let focused = app.focus == Focus::Xrefs;
    let title = format!("xrefs to 0x{:x} ({})", at + app.an.display_base, refs.len());

    let items: Vec<ListItem> = if refs.is_empty() {
        vec![ListItem::new(TLine::from(Span::styled(
            " no references",
            Style::default().fg(faint()),
        )))]
    } else {
        refs.iter()
            .map(|x| {
                let site = match app.an.function_at(x.from) {
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
                ListItem::new(TLine::from(vec![
                    Span::styled(
                        format!(" {:>12x}  ", x.from + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(
                        format!("{:<7}", x.kind.label()),
                        Style::default().fg(match x.kind {
                            XrefKind::Call => mint(),
                            XrefKind::Data => muted(),
                            _ => amber(),
                        }),
                    ),
                    Span::styled(site, Style::default().fg(muted())),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    if !refs.is_empty() {
        state.select(Some(app.xsel.min(refs.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(Style::default().bg(Color::Rgb(0x2a, 0x26, 0x3a)))
            .highlight_symbol("›"),
        area,
        &mut state,
    );
}

fn footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some(p) = &app.prompt {
        let line = TLine::from(vec![
            Span::styled(
                format!(" {}: ", p.ask.label()),
                Style::default().fg(accent()).add_modifier(Modifier::BOLD),
            ),
            Span::raw(p.input.clone()),
            Span::styled("█", Style::default().fg(accent())),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }

    if !app.status.is_empty() {
        f.render_widget(
            Paragraph::new(TLine::from(Span::styled(
                format!(" {}", app.status),
                Style::default().fg(amber()),
            ))),
            area,
        );
        return;
    }

    f.render_widget(
        Paragraph::new(TLine::from(Span::styled(
            format!(
                " db {} · ↵ open/follow{jump} ⌫ back   {find}   g goto   s {left}   d {mode}   n name   c note   ? help   q quit",
                app.db.len(),
                jump = if app.focus == Focus::Xrefs {
                    " (jump to ref)"
                } else {
                    ""
                },
                find = if app.focus == Focus::Listing { "/ search" } else { "/ filter" },
                left = if app.left == LeftView::Sinks { "funcs" } else { "sinks" },
                mode = if app.pseudo { "asm" } else { "pseudo" },
            ),
            Style::default().fg(faint()),
        ))),
        area,
    );
}

fn help(f: &mut Frame, area: Rect) {
    let text = vec![
        "",
        "  ↑ ↓ / j k      move            tab            switch pane",
        "                  (functions / listing / xrefs)",
        "  pgup pgdn      page            home end       first / last",
        "  mouse          wheel scrolls, click picks a pane and an entry",
        "  ↵              open a function, follow the call under the cursor,",
        "                 or jump to a reference in the xrefs pane; following a",
        "                 string operand opens its bytes as a hex dump",
        "  ⌫              back to where you followed from",
        "",
        "  /              filter the function list, or search the code when the",
        "                 listing is focused (/↵ repeats, jumping to the next hit)",
        "  s              toggle the left pane between functions and sinks (the",
        "                 ranked attack surface); ↵ on a sink jumps to its call",
        "  g              go to an address or a symbol",
        "  d              toggle decompiled pseudocode for the current function",
        "  n              name what is under the cursor (empty clears it)",
        "  c              note what is under the cursor (empty clears it)",
        "  r              re-analyse",
        "",
        "  Names and notes are written to the database as you make them, so",
        "  they are already saved when you quit.",
        "",
        "  any key to dismiss",
    ];
    let w = 74.min(area.width.saturating_sub(4));
    let h = (text.len() as u16 + 2).min(area.height);
    let box_area = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, box_area);
    f.render_widget(
        Paragraph::new(
            text.into_iter()
                .map(|l| TLine::from(Span::styled(l, Style::default().fg(muted()))))
                .collect::<Vec<_>>(),
        )
        .block(pane("keys", true)),
        box_area,
    );
}

/// A ` · row/total` suffix for a pane title, so the position in a long listing
/// is visible; empty when there is nothing to place.
fn position(cursor: usize, total: usize) -> String {
    if total == 0 {
        String::new()
    } else {
        format!(" · {}/{}", cursor + 1, total)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        format!("{s:<max$}")
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}
