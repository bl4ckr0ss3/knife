//! Drawing. Reads `App` and never changes it.
//!
//! Monochrome debugger palette: hierarchy and focus, not decorative syntax hues.

use super::{
    graph_horizontal_offset, graph_layout, graph_view_offset, App, Focus, LeftView, Line, RefView,
    GRAPH_NODE_WIDTH,
};
use crate::listing::Annot;
use iced_x86::FlowControl;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Frame;

pub(crate) fn accent() -> Color {
    Color::Rgb(0xf0, 0xf0, 0xf0)
}
fn critical() -> Color {
    Color::Rgb(0xff, 0xff, 0xff)
}
pub(crate) fn muted() -> Color {
    Color::Rgb(0xc0, 0xc0, 0xc0)
}
pub(crate) fn faint() -> Color {
    Color::Rgb(0x88, 0x88, 0x88)
}
pub(crate) fn mint() -> Color {
    Color::Rgb(0xd8, 0xd8, 0xd8)
}
pub(crate) fn amber() -> Color {
    Color::Rgb(0xe0, 0xe0, 0xe0)
}
pub(crate) fn canvas() -> Color {
    Color::Rgb(0x00, 0x00, 0x00)
}
pub(crate) fn panel() -> Color {
    Color::Rgb(0x12, 0x12, 0x12)
}
pub(crate) fn selected() -> Style {
    Style::default()
        .fg(Color::Rgb(0xff, 0xff, 0xff))
        .bg(Color::Rgb(0x38, 0x38, 0x38))
        .add_modifier(Modifier::BOLD)
}

pub(crate) fn pane(title: &str, focused: bool) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .style(Style::default().fg(muted()).bg(panel()))
        .border_style(Style::default().fg(if focused { accent() } else { faint() }))
        .title(Span::styled(
            format!("{} {title} ", if focused { ">" } else { " " }),
            Style::default()
                .fg(if focused { canvas() } else { muted() })
                .bg(if focused { accent() } else { panel() })
                .add_modifier(if focused {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ))
}

/// The parts of a function row that never change size: the address and the
/// incoming-call count. The name takes the rest.
const FIXED_FUNCTION_COLUMNS: usize = 15;

/// The parts of a sink row that never change size: the severity mark and the
/// address. Whatever the pane has left over is split between the two names.
const FIXED_SINK_COLUMNS: usize = 14;

/// Center the selected row when possible. Renderers and mouse hit testing use
/// the same window so a click always selects the row drawn beneath it.
pub(crate) fn viewport_start(selection: usize, total: usize, height: usize) -> usize {
    selection
        .saturating_sub(height / 2)
        .min(total.saturating_sub(height))
}

fn list_height(area: Rect) -> usize {
    usize::from(area.height.saturating_sub(2))
}

pub fn loading(f: &mut Frame, title: &str, elapsed_seconds: u64) {
    let title: String = title
        .chars()
        .map(|ch| if ch.is_control() { '.' } else { ch })
        .collect();
    let text = format!("KNIFE | {title}\n\nRecovering functions and preparing analysis views...\nElapsed: {elapsed_seconds}s | progress total unavailable\n\nq / Esc / Ctrl+C: quit");
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(muted()).bg(canvas())),
        f.area(),
    );
}

pub fn draw(f: &mut Frame, app: &App) {
    if app.splash {
        super::splash::draw(f, f.area(), app.frame, false);
        return;
    }
    // Below this size no pane carries enough content to read; say so instead
    // of drawing a misleading mosaic of fragments.
    let area = f.area();
    if area.width < 24 || area.height < 6 {
        f.render_widget(
            Paragraph::new("KNIFE\n\nterminal too small; resize the window")
                .style(Style::default().fg(muted()).bg(canvas()))
                .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
        return;
    }
    f.render_widget(
        Block::default().style(Style::default().fg(muted()).bg(canvas())),
        f.area(),
    );

    let panes = app.panes(f.area());
    header(f, panes.header, app);
    if panes.functions.width > 0 {
        functions(f, panes.functions, app);
    }
    if app.split {
        // Stable columns: the active state is drawn in whichever column owns
        // it, so content never jumps sides on a pane switch.
        let (left, right) = if app.active_is_left {
            (app.active_view(), app.other_view())
        } else {
            (app.other_view(), app.active_view())
        };
        listing(f, panes.listing, app, &left);
        listing(f, panes.listing_right, app, &right);
    } else {
        listing(f, panes.listing, app, &app.active_view());
        if panes.references.width > 0 && panes.references.height > 0 {
            xrefs(f, panes.references, app);
        }
    }
    if panes.detail.height > 0 {
        if app.left == LeftView::Types {
            type_detail(f, panes.detail, app);
        } else {
            evidence(f, panes.detail, app);
        }
    }
    footer(f, panes.footer, app);

    if app.investigation_open {
        investigation_desk(f, app);
    }

    if app.help {
        help(f, f.area(), app);
    }
}

fn investigation_desk(f: &mut Frame, app: &App) {
    let desk = app.panes(f.area()).agent;
    let width = desk.width;
    f.render_widget(Clear, desk);
    let conversation_height = desk.height / 2;
    let conversation_area = Rect::new(desk.x, desk.y, desk.width, conversation_height);
    let message = app
        .investigation
        .messages
        .iter()
        .rev()
        .nth(app.investigation_message_offset);
    let conversation = message.map(|message|format!("{:?}\n{}",message.role,message.text)).unwrap_or_else(||"Press i to speak to the agent.\nPgUp/PgDn: conversation history\nCtrl+Up/Down: scroll message\nEnter: follow selected evidence\nCtrl+Tab: switch workspace/chat\nf: toggle live following\nCtrl+C: interrupt agent\nSet KNIFE_AGENT_MODEL for local Ollama; external agents use MCP.".into());
    let conversation = if app.investigation_evidence_detail {
        app.investigation
            .evidence
            .values()
            .nth(app.investigation_selection)
            .map(|record| {
                let mut text = format!(
                    "{}\nProducer: {}\n{}\n",
                    record.id.0, record.producer, record.summary
                );
                for location in &record.locations {
                    if let Some(address) = location.static_address {
                        text.push_str(&format!("Static: 0x{:x}\n", address.get()));
                    }
                    if let Some(offset) = location.file_offset {
                        text.push_str(&format!("File: 0x{:x}\n", offset.get()));
                    }
                    if let Some(address) = location.runtime_address {
                        text.push_str(&format!("Runtime: 0x{:x}\n", address.get()));
                    }
                }
                for statement in &record.statements {
                    text.push_str(&format!(
                        "{:?} / {:?}: {}\n",
                        statement.kind, statement.confidence, statement.text
                    ));
                }
                for limitation in &record.limitations {
                    text.push_str(&format!("Limitation: {limitation}\n"));
                }
                text
            })
            .unwrap_or_else(|| "No evidence selected. Press e to return to conversation.".into())
    } else {
        conversation
    };
    f.render_widget(
        Paragraph::new(conversation)
            .block(Block::default().borders(Borders::ALL).title(
                if app.investigation_evidence_detail {
                    " Investigation desk — evidence "
                } else {
                    " Investigation desk — Agent chat "
                },
            ))
            .style(Style::default().fg(accent()).bg(panel()))
            .wrap(Wrap { trim: false })
            .scroll((app.investigation_message_scroll, 0)),
        conversation_area,
    );
    let desk = Rect::new(
        desk.x,
        desk.y.saturating_add(conversation_height),
        desk.width,
        desk.height.saturating_sub(conversation_height),
    );
    let mut lines = vec![
        TLine::from(format!(
            " i: chat  f: follow {}  Ctrl+Tab: {}",
            if app.investigation_follow {
                "ON"
            } else {
                "OFF"
            },
            if app.investigation_focused {
                "workspace"
            } else {
                "chat"
            }
        )),
        TLine::from(" Findings and activity"),
    ];
    lines.insert(
        1,
        TLine::from(format!(" Activity: {}", app.investigation_activity)),
    );
    lines.push(TLine::from(if app.investigation_conflicts_only {
        " Conflicting evidence — review required"
    } else {
        " Questions and hypotheses"
    }));
    for step in app
        .investigation
        .plan
        .iter()
        .filter(|step| step.status != crate::api::investigation::PlanStatus::Completed)
        .take(2)
    {
        lines.push(TLine::from(format!(
            " Plan #{} {:?}: {}",
            step.id,
            step.status,
            desk_preview(&step.text, usize::from(width.saturating_sub(25)))
        )));
    }
    let hypotheses: Vec<_> = app
        .investigation
        .hypotheses
        .iter()
        .rev()
        .filter(|hypothesis| {
            !app.investigation_conflicts_only
                || (!hypothesis.supports.is_empty() && !hypothesis.contradicts.is_empty())
        })
        .take(2)
        .collect();
    if app.investigation_conflicts_only && hypotheses.is_empty() {
        lines.push(TLine::from(
            " No conflicting links recorded; absence is not proof.",
        ));
    }
    for hypothesis in hypotheses {
        lines.push(TLine::from(format!(
            " #{} {:?}: {}",
            hypothesis.id,
            hypothesis.status,
            desk_preview(&hypothesis.question, usize::from(width.saturating_sub(25)))
        )));
        if app.investigation_conflicts_only {
            lines.push(TLine::from(format!(" {} supporting / {} contradicting records (#{}); inspect via MCP investigation_conflicts",hypothesis.supports.len(),hypothesis.contradicts.len(),hypothesis.id)));
        }
    }
    lines.push(TLine::from(
        " Evidence — Up/Down; e inspects; Enter follows",
    ));
    let evidence_height = usize::from(desk.height.saturating_sub(2)).saturating_sub(lines.len());
    let evidence_start = viewport_start(
        app.investigation_selection,
        app.investigation.evidence.len(),
        evidence_height,
    );
    for (index, record) in app
        .investigation
        .evidence
        .values()
        .enumerate()
        .skip(evidence_start)
        .take(evidence_height)
    {
        lines.push(TLine::styled(
            format!(
                " {} {}",
                if index == app.investigation_selection {
                    ">"
                } else {
                    " "
                },
                desk_preview(&record.summary, usize::from(width.saturating_sub(6)))
            ),
            Style::default().fg(if index == app.investigation_selection {
                accent()
            } else {
                muted()
            }),
        ));
    }
    f.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Investigation desk "),
            )
            .style(Style::default().fg(accent()).bg(panel()))
            .wrap(Wrap { trim: false }),
        desk,
    );
}

fn desk_preview(text: &str, limit: usize) -> String {
    let mut characters = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch });
    let mut result: String = characters.by_ref().take(limit.saturating_sub(1)).collect();
    if characters.next().is_some() {
        result.push('…');
    }
    result
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let named = app.an.functions.iter().filter(|x| x.named).count();
    let high = app
        .sinks
        .iter()
        .filter(|finding| finding.severity >= 3)
        .count();
    let line = TLine::from(vec![
        Span::styled(
            format!(" KNIFE  {} ", app.title),
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "{}  {}  │  {} functions  {} named  │  {} high-risk",
                app.bin.format.label(),
                app.bin.arch.label(),
                app.an.functions.len(),
                named,
                high,
            ),
            Style::default().fg(faint()),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn functions(f: &mut Frame, area: Rect, app: &App) {
    if let Some(browser) = &app.browser {
        catalog(f, area, app, browser);
        return;
    }
    if app.left == LeftView::Sinks {
        sinks(f, area, app);
        return;
    }
    if app.left == LeftView::Driver {
        driver_view(f, area, app);
        return;
    }
    if app.left == LeftView::Types {
        type_browser(f, area, app);
        return;
    }
    let focused = app.focus == Focus::Functions;
    // The function containing whatever the listing shows is marked, so moving
    // through code keeps the left pane in step even after following calls.
    let current = app.cur;
    // Demangled C++ names are long; give them whatever the pane has spare once
    // the address and the caller count have taken their fixed columns.
    let name_w = usize::from(area.width.saturating_sub(3))
        .saturating_sub(FIXED_FUNCTION_COLUMNS)
        .clamp(8, 40);
    let height = list_height(area);
    let start = viewport_start(app.sel, app.order.len(), height);
    let items: Vec<ListItem> = app
        .order
        .iter()
        .skip(start)
        .take(height)
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
                truncate(&fun.name, name_w),
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
        state.select(Some(app.sel - start));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

/// The attack surface: ranked sink call sites, most severe first.
fn catalog(f: &mut Frame, area: Rect, app: &App, browser: &super::browser::Browser) {
    let height = usize::from(area.height.saturating_sub(2))
        .div_ceil(2)
        .max(1);
    let start = viewport_start(browser.selection, browser.visible.len(), height);
    let items: Vec<ListItem> = browser
        .visible
        .iter()
        .skip(start)
        .take(height)
        .map(|index| {
            let row = &browser.rows[*index];
            let address = row
                .address
                .map(|value| format!("VA {:x}", value.get()))
                .unwrap_or_else(|| {
                    if row.file_offset.is_some() {
                        "FILE".into()
                    } else {
                        "VA unresolved".into()
                    }
                });
            let offset = row
                .file_offset
                .map(|value| format!(" OFF {:x}", value.get()))
                .unwrap_or_default();
            let label: String = row
                .label
                .chars()
                .map(|ch| if ch.is_control() { '.' } else { ch })
                .collect();
            ListItem::new(vec![
                TLine::from(Span::styled(
                    truncate(&label, usize::from(area.width.saturating_sub(3))),
                    Style::default().fg(mint()),
                )),
                TLine::from(Span::styled(
                    format!("{address}{offset} {}", row.detail),
                    Style::default().fg(muted()),
                )),
            ])
        })
        .collect();
    let title = format!(
        "{} {} /{}",
        browser.catalog.title(),
        browser.visible.len(),
        browser.filter
    );
    let mut state = ListState::default();
    if !browser.visible.is_empty() {
        state.select(Some(browser.selection - start));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, app.focus == Focus::Functions))
            .highlight_style(selected())
            .highlight_symbol(">"),
        area,
        &mut state,
    );
}

fn sinks(f: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Functions;
    // Split the row across the pane it is actually being drawn into: two
    // borders and the selection marker are gone before any text, and what is
    // left is shared between the bug class and the function it sits in. Both
    // are names, and a name cut in half tells you nothing.
    let inner = usize::from(area.width.saturating_sub(3));
    let rest = inner.saturating_sub(FIXED_SINK_COLUMNS);
    let pattern_w = rest.saturating_sub(8).clamp(6, 14);
    let name_w = rest.saturating_sub(pattern_w + 1).max(4);

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
                    3 => ("H", critical()),
                    2 => ("M", amber()),
                    _ => ("L", muted()),
                };
                let where_ = s.func.as_deref().unwrap_or("-");
                ListItem::new(TLine::from(vec![
                    Span::styled(
                        format!("[{mark}] "),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{} ", truncate(&s.pattern.replace('-', " "), pattern_w)),
                        Style::default().fg(color),
                    ),
                    Span::styled(
                        format!("{:>9x} ", s.addr + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(truncate(where_, name_w), Style::default().fg(muted())),
                ]))
            })
            .collect()
    };

    let title = format!("attack surface ({})", app.sinks.len());
    let mut state = ListState::default();
    if !app.sinks.is_empty() {
        state.select(Some(app.ssel.min(app.sinks.len() - 1)));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

/// The kernel-driver summary: identity, devices, IRP dispatch, IOCTL surface,
/// and the primitives with their call counts. Read-only, so it renders as a
/// wrapped paragraph rather than a selectable list.
fn driver_view(f: &mut Frame, area: Rect, app: &App) {
    let is_driver = app.driver.as_ref().is_some_and(|d| d.is_driver);
    let focused = app.focus == Focus::Functions;
    let fg = |c: Color| Style::default().fg(c);

    let rows = app.driver_rows();
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| {
            if r.section {
                ListItem::new(TLine::from(Span::styled(
                    format!("{} {}", r.label, r.detail),
                    fg(amber()).add_modifier(Modifier::BOLD),
                )))
            } else {
                let mut spans = Vec::new();
                let mark = if r.accent { "!" } else { "·" };
                spans.push(Span::styled(
                    mark,
                    fg(if r.accent { accent() } else { muted() }),
                ));
                spans.push(Span::styled(
                    format!(" {:<22}", truncate(&r.label, 22)),
                    fg(if r.faint {
                        muted()
                    } else if r.accent {
                        accent()
                    } else {
                        mint()
                    }),
                ));
                spans.push(Span::styled(format!(" {}", r.detail), fg(faint())));
                ListItem::new(TLine::from(spans))
            }
        })
        .collect();

    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(app.dsel.min(rows.len() - 1)));
    }
    let title = format!(
        "driver{} {}{}",
        if is_driver { "" } else { " (not native)" },
        if app.dsrch.is_empty() {
            "".to_string()
        } else {
            format!("/{} ", app.dsrch)
        },
        if app.dreach { "[reachable]" } else { "" }
    );
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

fn type_browser(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.type_rows();
    let focused = app.focus == Focus::Functions;
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| {
            if row.section {
                ListItem::new(TLine::from(Span::styled(
                    format!(" {}", row.label),
                    Style::default().fg(amber()).add_modifier(Modifier::BOLD),
                )))
            } else {
                let color = match row.kind {
                    "prototype" => mint(),
                    "layout" => accent(),
                    "binding" => amber(),
                    "variable" => mint(),
                    _ => muted(),
                };
                ListItem::new(TLine::from(vec![
                    Span::styled("· ", Style::default().fg(color)),
                    Span::styled(
                        format!("{:<20}", truncate(&row.label, 20)),
                        Style::default().fg(color),
                    ),
                    Span::styled(truncate(&row.detail, 13), Style::default().fg(faint())),
                ]))
            }
        })
        .collect();
    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(app.tsel.min(rows.len() - 1)));
    }
    let title = if app.tysrch.is_empty() {
        format!(
            "types ({})",
            app.db.prototypes.len()
                + app.db.fields.len()
                + app.db.bindings.len()
                + app.db.variables.len()
        )
    } else {
        format!("types /{}", app.tysrch)
    };
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

fn listing(f: &mut Frame, area: Rect, app: &App, view: &super::ListingViewRef) {
    if view.graph {
        function_graph(f, area, app, view);
        return;
    }
    if view.pseudo {
        pseudo(f, area, app, view);
        return;
    }
    let focused = view.focused;
    let title = if view.raw_file {
        match view.cur {
            Some(offset) => format!(
                "raw file @ OFF 0x{offset:x}{}",
                position(view.cursor, view.lines.len())
            ),
            None => "raw file".into(),
        }
    } else {
        match view.cur {
            Some(a) => format!(
                "{} @ 0x{:x}{}",
                app.an.label(a),
                a + app.an.display_base,
                position(view.cursor, view.lines.len())
            ),
            None => "listing".into(),
        }
    };

    let height = list_height(area);
    let start = viewport_start(view.cursor, view.lines.len(), height);
    let items: Vec<ListItem> = view
        .lines
        .iter()
        .skip(start)
        .take(height)
        .map(|l| match l {
            Line::Label { text, .. } => ListItem::new(TLine::from(Span::styled(
                format!("  {text}:"),
                Style::default().fg(amber()),
            ))),
            Line::Data { addr, text } => ListItem::new(TLine::from(vec![
                Span::styled(
                    if view.raw_file {
                        format!("OFF {:08x}  ", addr)
                    } else {
                        format!("{:012x}  ", addr + app.an.display_base)
                    },
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
                        // A derived type hint is tooling notes, drawn faint.
                        Annot::Hint(t) => (t.clone(), faint()),
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
    if !view.lines.is_empty() {
        state.select(Some(view.cursor - start));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

fn function_graph(f: &mut Frame, area: Rect, app: &App, view: &super::ListingViewRef) {
    let focused = view.focused;
    let Some(function) = view.cur.and_then(|address| app.an.find_function(address)) else {
        f.render_widget(
            Paragraph::new(" Open a recovered function, then press f.")
                .style(Style::default().fg(faint()))
                .block(pane("function graph", focused)),
            area,
        );
        return;
    };
    let index: std::collections::BTreeMap<u64, usize> = function
        .blocks
        .iter()
        .enumerate()
        .map(|(i, block)| (block.start, i))
        .collect();
    let title = format!(
        "function graph · {} · {} blocks{} · arrows move · ↵ opens",
        function.name,
        function.blocks.len(),
        position(view.cursor, function.blocks.len())
    );
    f.render_widget(pane(&title, focused), area);
    let inner = Rect::new(
        area.x.saturating_add(1),
        area.y.saturating_add(1),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    if inner.is_empty() {
        return;
    }
    let inspector_height = if inner.height >= 9 { 6 } else { 0 };
    let map = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(inspector_height),
    );
    let inspector = Rect::new(
        inner.x,
        map.y.saturating_add(map.height),
        inner.width,
        inspector_height,
    );
    let layout = graph_layout(function, map.width);
    let offset = graph_view_offset(&layout, view.cursor, map.height);
    let horizontal = graph_horizontal_offset(&layout, view.cursor, map.width);

    // Edges are routed before nodes so node labels remain crisp where paths
    // meet. Back/cross edges stay on the source row and carry a return marker.
    for (source_index, block) in function.blocks.iter().enumerate() {
        let Some(source) = layout.nodes.iter().find(|node| node.index == source_index) else {
            continue;
        };
        let conditional = block.insns.last().is_some_and(|instruction| {
            instruction.flow == FlowControl::ConditionalBranch && block.succ.len() >= 2
        });
        for successor in &block.succ {
            let Some(&target_index) = index.get(successor) else {
                continue;
            };
            let Some(target) = layout.nodes.iter().find(|node| node.index == target_index) else {
                continue;
            };
            let color = if conditional { amber() } else { accent() };
            if target.y <= source.y {
                let y = source.y.saturating_sub(offset);
                if y < map.height {
                    let x = source.x.saturating_add(GRAPH_NODE_WIDTH);
                    if x >= horizontal && x - horizontal < map.width {
                        let visible_x = x - horizontal;
                        f.buffer_mut().set_stringn(
                            map.x.saturating_add(visible_x),
                            map.y.saturating_add(y),
                            format!("↑B{target_index:02}"),
                            map.width.saturating_sub(visible_x) as usize,
                            Style::default().fg(amber()),
                        );
                    }
                }
                continue;
            }
            let sx = source.x.saturating_add(GRAPH_NODE_WIDTH / 2);
            let tx = target.x.saturating_add(GRAPH_NODE_WIDTH / 2);
            let bend = target.y.saturating_sub(1);
            for logical_y in source.y.saturating_add(1)..=bend {
                if logical_y < offset || logical_y - offset >= map.height {
                    continue;
                }
                let symbol = if logical_y == bend { "─" } else { "│" };
                if sx >= horizontal && sx - horizontal < map.width {
                    f.buffer_mut().set_string(
                        map.x.saturating_add(sx - horizontal),
                        map.y.saturating_add(logical_y - offset),
                        symbol,
                        Style::default().fg(color),
                    );
                }
            }
            if bend >= offset && bend - offset < map.height {
                let y = map.y.saturating_add(bend - offset);
                for x in sx.min(tx)..=sx.max(tx) {
                    if x >= horizontal && x - horizontal < map.width {
                        f.buffer_mut().set_string(
                            map.x.saturating_add(x - horizontal),
                            y,
                            "─",
                            Style::default().fg(color),
                        );
                    }
                }
                if tx >= horizontal && tx - horizontal < map.width {
                    f.buffer_mut().set_string(
                        map.x.saturating_add(tx - horizontal),
                        y,
                        "▼",
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    );
                }
            }
        }
    }

    for node in &layout.nodes {
        if node.y < offset || node.y - offset >= map.height {
            continue;
        }
        let block = &function.blocks[node.index];
        let terminal = block.succ.is_empty();
        let is_selected = node.index == view.cursor;
        let text = if is_selected {
            format!("▶B{:02}◀", node.index)
        } else {
            format!("[B{:02}]", node.index)
        };
        let color = if is_selected {
            Color::Black
        } else if terminal {
            critical()
        } else if node.index == 0 {
            mint()
        } else {
            accent()
        };
        let style = Style::default()
            .fg(color)
            .bg(if is_selected { accent() } else { panel() })
            .add_modifier(Modifier::BOLD);
        if node.x < horizontal || node.x >= horizontal.saturating_add(map.width) {
            continue;
        }
        let visible_x = node.x.saturating_sub(horizontal);
        f.buffer_mut().set_stringn(
            map.x.saturating_add(visible_x),
            map.y.saturating_add(node.y - offset),
            text,
            GRAPH_NODE_WIDTH.min(map.width.saturating_sub(visible_x)) as usize,
            style,
        );
    }

    if inspector.height > 0 {
        let selected_index = view.cursor.min(function.blocks.len().saturating_sub(1));
        if let Some(block) = function.blocks.get(selected_index) {
            let calls = block
                .insns
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction.flow,
                        FlowControl::Call | FlowControl::IndirectCall
                    )
                })
                .count();
            let mut lines = vec![TLine::from(vec![
                Span::styled(
                    format!(" B{selected_index:02} "),
                    Style::default()
                        .fg(Color::Black)
                        .bg(accent())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!(
                        " 0x{:x} · {} insns{}  ",
                        block.start + app.an.display_base,
                        block.insns.len(),
                        if calls > 0 {
                            format!(" · {calls} calls")
                        } else {
                            String::new()
                        }
                    ),
                    Style::default().fg(faint()),
                ),
            ])];
            lines.push(graph_edges(block, &index));
            for instruction in block
                .insns
                .iter()
                .take(inspector.height.saturating_sub(2) as usize)
            {
                lines.push(TLine::from(vec![
                    Span::styled(
                        format!(" {:x}  ", instruction.addr + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(
                        truncate(
                            &instruction.text(app.an.bits, app.an.arch),
                            inner.width.saturating_sub(16).max(8) as usize,
                        ),
                        Style::default().fg(muted()),
                    ),
                ]));
            }
            f.render_widget(
                Paragraph::new(lines).block(
                    Block::default()
                        .borders(Borders::TOP)
                        .border_style(Style::default().fg(faint())),
                ),
                inspector,
            );
        }
    }
}

fn graph_edges(
    block: &crate::analysis::engine::BasicBlock,
    index: &std::collections::BTreeMap<u64, usize>,
) -> TLine<'static> {
    let mut spans = vec![Span::styled("╰─ ", Style::default().fg(accent()))];
    let last = block.insns.last();
    if last.is_some_and(|instruction| instruction.flow == FlowControl::Return) {
        spans.push(Span::styled(
            "RETURN",
            Style::default().fg(critical()).add_modifier(Modifier::BOLD),
        ));
        return TLine::from(spans);
    }
    if block.succ.is_empty() {
        spans.push(Span::styled("TERMINAL", Style::default().fg(critical())));
        return TLine::from(spans);
    }
    let conditional = last.is_some_and(|instruction| {
        instruction.flow == FlowControl::ConditionalBranch && block.succ.len() >= 2
    });
    for (position, successor) in block.succ.iter().enumerate() {
        if position > 0 {
            spans.push(Span::styled("   ", Style::default().fg(faint())));
        }
        let label = if conditional {
            if last.and_then(|instruction| instruction.target) == Some(*successor) {
                "TRUE"
            } else {
                "FALSE"
            }
        } else {
            "FLOW"
        };
        let target = index
            .get(successor)
            .map(|i| format!("B{i:02}"))
            .unwrap_or_else(|| format!("0x{successor:x}"));
        spans.push(Span::styled(
            format!("{label} → {target}"),
            Style::default()
                .fg(if conditional { amber() } else { accent() })
                .add_modifier(Modifier::BOLD),
        ));
    }
    TLine::from(spans)
}

/// Colour a line of pseudocode: keywords stand out, everything else is muted.
fn pseudo_spans(text: &str) -> Vec<Span<'static>> {
    const KW: &[&str] = &[
        "if", "else", "while", "switch", "case", "break", "continue", "goto", "return", "do", "for",
    ];
    const TYPES: &[&str] = &[
        "void",
        "bool",
        "int",
        "size_t",
        "ssize_t",
        "uintptr_t",
        "uint8_t",
        "wchar_t",
        "char",
    ];
    let mut spans = Vec::new();
    let mut buf = String::new();
    let mut buf_word = false;
    let mut after_arrow = false;
    let flush = |buf: &mut String, word: bool, member: bool, spans: &mut Vec<Span<'static>>| {
        if buf.is_empty() {
            return;
        }
        let color = if word {
            if KW.contains(&buf.as_str()) {
                accent()
            } else if member || TYPES.contains(&buf.as_str()) || buf.starts_with("field_") {
                mint()
            } else {
                muted()
            }
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
            if buf_word {
                flush(&mut buf, true, after_arrow, &mut spans);
                after_arrow = false;
            } else {
                after_arrow = buf.ends_with("->");
                flush(&mut buf, false, false, &mut spans);
            }
            buf_word = word;
        }
        buf.push(ch);
    }
    flush(&mut buf, buf_word, buf_word && after_arrow, &mut spans);
    spans
}

fn pseudo(f: &mut Frame, area: Rect, app: &App, view: &super::ListingViewRef) {
    let focused = view.focused;
    let title = match view.cur {
        Some(a) => format!(
            "pseudocode · {} @ 0x{:x}{}",
            app.an.label(a),
            a + app.an.display_base,
            position(view.cursor, view.pseudo_lines.len())
        ),
        None => "pseudocode".into(),
    };

    let height = list_height(area);
    let start = viewport_start(view.cursor, view.pseudo_lines.len(), height);
    let mut items: Vec<ListItem> = view
        .pseudo_lines
        .iter()
        .skip(start)
        .take(height)
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
    if !view.pseudo_lines.is_empty() {
        state.select(Some(view.cursor.min(view.pseudo_lines.len() - 1) - start));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

fn type_detail(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.type_rows();
    let Some(row) = rows.get(app.tsel) else {
        return;
    };
    let address = row
        .addr
        .map(|address| format!("0x{:x}", address + app.an.display_base))
        .unwrap_or_else(|| "layout fact".into());
    let color = match row.kind {
        "prototype" => mint(),
        "layout" => accent(),
        "binding" => amber(),
        "variable" => mint(),
        _ => muted(),
    };
    let lines = vec![
        TLine::from(vec![
            Span::styled(" kind     ", Style::default().fg(faint())),
            Span::styled(
                row.kind.to_uppercase(),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   owner  ", Style::default().fg(faint())),
            Span::styled(row.label.clone(), Style::default().fg(mint())),
            Span::styled("   at  ", Style::default().fg(faint())),
            Span::styled(address, Style::default().fg(muted())),
        ]),
        TLine::from(vec![
            Span::styled(" fact     ", Style::default().fg(faint())),
            Span::styled(row.detail.clone(), Style::default().fg(color)),
        ]),
        TLine::from(Span::styled(
            if row.addr.is_some() {
                " enter opens the owning function · p/l/t/e edits in pseudocode"
            } else {
                " structure fields are reusable across scoped pointer bindings"
            },
            Style::default().fg(faint()),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(pane("type fact", false).border_style(Style::default().fg(color))),
        area,
    );
}

fn evidence(f: &mut Frame, area: Rect, app: &App) {
    let Some(finding) = app.sinks.get(app.ssel) else {
        return;
    };
    let (level, color) = match finding.severity {
        3 => ("HIGH", critical()),
        2 => ("MEDIUM", amber()),
        _ => ("LOW", muted()),
    };
    let reach = if finding.reachable {
        "REACHABLE"
    } else {
        "UNPROVEN"
    };
    let function = finding.func.as_deref().unwrap_or("unknown function");
    let lines = vec![
        TLine::from(vec![
            Span::styled(" pattern  ", Style::default().fg(faint())),
            Span::styled(
                finding.pattern,
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   sink  ", Style::default().fg(faint())),
            Span::styled(
                format!("{} @ 0x{:x}", finding.api, finding.addr),
                Style::default().fg(mint()),
            ),
        ]),
        TLine::from(vec![
            Span::styled(" signal   ", Style::default().fg(faint())),
            Span::styled(
                evidence_chain(&finding.detail, &finding.api),
                Style::default().fg(amber()),
            ),
            Span::styled("   in  ", Style::default().fg(faint())),
            Span::styled(function, Style::default().fg(muted())),
        ]),
        TLine::from(vec![
            Span::styled(" why      ", Style::default().fg(faint())),
            Span::styled(finding.detail.clone(), Style::default().fg(muted())),
        ]),
    ];
    let title = format!("evidence · {level} · {reach}");
    let block = pane(&title, false).border_style(Style::default().fg(color));
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(block),
        area,
    );
}

fn evidence_chain(detail: &str, api: &str) -> String {
    let source = if detail.contains("external-input API") {
        "EXTERNAL INPUT"
    } else if detail.contains("function argument") {
        "ARGUMENT"
    } else if detail.contains("some incoming paths") {
        "CFG MERGE"
    } else if detail.contains("subtraction") {
        "SUBTRACTION"
    } else if detail.contains("multiplication") {
        "MULTIPLICATION"
    } else if detail.contains("stack buffer") {
        "STACK BUFFER"
    } else {
        "RUNTIME VALUE"
    };
    format!("{source} → DATA FLOW → {}", api.to_uppercase())
}

fn xrefs(f: &mut Frame, area: Rect, app: &App) {
    let rows = app.xref_rows();
    let focused = app.focus == Focus::Xrefs;
    let title = match app.refview {
        RefView::To => format!(
            "xrefs to 0x{:x} ({})",
            app.xref_at() + app.an.display_base,
            rows.len()
        ),
        RefView::Callers => {
            let name = app.cur.map(|a| app.an.label(a)).unwrap_or_default();
            format!("callers of {name} ({})", rows.len())
        }
        RefView::From => {
            let name = app.cur.map(|a| app.an.label(a)).unwrap_or_default();
            format!("calls from {name} ({})", rows.len())
        }
    };

    let empty = if app.refview == RefView::To {
        " no recovered references; indirect reachability unknown"
    } else {
        " no recovered calls; unresolved indirect calls may exist"
    };
    let height = list_height(area);
    let selected_row = app.xsel.min(rows.len().saturating_sub(1));
    let start = viewport_start(selected_row, rows.len(), height);
    let items: Vec<ListItem> = if rows.is_empty() {
        vec![ListItem::new(TLine::from(Span::styled(
            empty,
            Style::default().fg(faint()),
        )))]
    } else {
        rows.iter()
            .skip(start)
            .take(height)
            .map(|row| {
                ListItem::new(TLine::from(vec![
                    Span::styled(
                        format!(" {:>12x}  ", row.site + app.an.display_base),
                        Style::default().fg(faint()),
                    ),
                    Span::styled(
                        format!("{:<7}", row.kind),
                        Style::default().fg(match row.kind {
                            "call" => mint(),
                            "data" => muted(),
                            _ => amber(),
                        }),
                    ),
                    Span::styled(row.label.clone(), Style::default().fg(muted())),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    if !rows.is_empty() {
        state.select(Some(selected_row - start));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(pane(&title, focused))
            .highlight_style(selected())
            .highlight_symbol("▸"),
        area,
        &mut state,
    );
}

fn footer(f: &mut Frame, area: Rect, app: &App) {
    if let Some(p) = &app.prompt {
        let line = TLine::from(vec![
            Span::styled(
                if p.ask == super::Ask::Command {
                    " : ".into()
                } else {
                    format!(" {}: ", p.ask.label())
                },
                Style::default().fg(accent()).add_modifier(Modifier::BOLD),
            ),
            Span::raw(p.input.clone()),
            Span::styled("█", Style::default().fg(accent())),
            Span::styled(format!("  {}", app.status), Style::default().fg(muted())),
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
            footer_hints(app.focus, area.width),
            Style::default().fg(muted()),
        ))),
        area,
    );
}

fn footer_hints(focus: Focus, width: u16) -> String {
    let name = match focus {
        Focus::Functions => "Browser",
        Focus::Listing => "Listing",
        Focus::Xrefs => "References",
    };
    let mut hints = format!(" {name} | : commands | ? help");
    let find = match focus {
        Focus::Listing => " | / search",
        Focus::Functions => " | / filter",
        Focus::Xrefs => "",
    };
    let enter = match focus {
        Focus::Functions => " | Enter open",
        Focus::Listing => " | Enter follow",
        Focus::Xrefs => " | Enter jump",
    };
    for hint in [
        " | Tab/S-Tab panes",
        " | +/- size",
        " | z zoom",
        enter,
        " | Backspace back",
        " | g goto",
        find,
        " | q quit",
    ] {
        if hints.len() + hint.len() <= usize::from(width) {
            hints.push_str(hint);
        }
    }
    hints
}

const HELP_LINES: &[&str] = &[
        "  ↑ ↓ / j k      move            Tab/Shift+Tab  next/previous pane",
        "  pgup pgdn      page            home end       first / last",
        "  mouse          wheel scrolls, click picks a pane and an entry",
        "  ↵              open, follow the call under the cursor, or jump to a",
        "                 reference; a string operand opens its bytes as a dump",
        "  Backspace      back to where you followed from",
        "  Alt+Left/Right back/forward, restoring view and cursor",
        "  :next/previous adjacent function in static-address order (no wrapping)",
        "  :split/:only   two listing columns; :compare F pins a function there",
        "  :history       browse/filter saved past and forward view locations",
        "  :focus PANE    functions, listing, references (reveals closed pane)",
        "  :close         close focused side pane; :widen/:narrow adjust width",
        "  + / -          grow / shrink focused pane; z maximize / restore",
        "  :              command mode; Tab completes, Up/Down recalls commands",
        "                 functions, function NAME, goto VA, cfg, disasm, decompile",
        "                 xrefs, callers, callees, types, rename NAME, comment TEXT, help",
        "                 catalogs: imports exports strings sections; ELF headers segments section-headers",
        "  b              toggle local bookmark; :bookmarks lists saved locations",
        "",
        "  /              filter the function list, or search the code when the",
        "                 listing is focused (/↵ repeats, jumping to the next hit)",
        "  s              cycle functions, sinks, driver, and analyst types;",
        "                 in types: I import, R replace, E export; ↵ opens owner",
        "  x              toggle the reference pane between callers (xrefs to the",
        "                 cursor) and callees (the calls the function makes)",
        "  g              go to address/symbol; off:0x.. offset, va:0x.. VA",
        "  r              re-analyse",
        "  :reload        re-read the target from disk; desk layout survives",
        "  d              toggle decompiled pseudocode for the current function",
        "  f              toggle the spatial control-flow graph; arrows move by",
        "                 layer/lane, click selects, ↵ opens the block in asm",
        "                 (↑ marks a loop or cross edge to an earlier layer)",
        "  t              bind/clear the selected pseudocode field base's type",
        "  e / l          edit the selected field / rename the line's variable",
        "  p              set/clear the current function prototype as",
        "                 RETURN (PARAM, PARAM), e.g. bool (CONTEXT *, size_t)",
        "  P              stage raw bytes at the selected assembly instruction;",
        "                 submit an empty value to restore its entire patch run",
        "  n              name what is under the cursor (empty clears it)",
        "  c              note what is under the cursor (empty clears it)",
        "",
        "  Names, notes, patches, variables, types, fields, and prototypes save",
        "  immediately; staged patches affect analysis but never modify the input;",
        "  they are already on disk when you quit.",
        "",
        "  ↑/↓ scroll, PgUp/PgDn page, Home/End jump; Esc or ? closes help",
    ];

fn help_geometry(area: Rect) -> Rect {
    let width = area.width.saturating_sub(2).min(76);
    let height = area.height.min(HELP_LINES.len() as u16 + 3);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

fn help_lines(width: usize) -> Vec<String> {
    let mut wrapped = Vec::new();
    for line in HELP_LINES {
        let mut rest = line.trim_end();
        if rest.is_empty() {
            wrapped.push(String::new());
            continue;
        }
        while rest.chars().count() > width {
            let limit = rest
                .char_indices()
                .nth(width)
                .map_or(rest.len(), |(i, _)| i);
            let cut = rest[..limit].rfind(' ').filter(|&i| i > 0).unwrap_or(limit);
            wrapped.push(rest[..cut].trim_end().to_string());
            rest = rest[cut..].trim_start();
        }
        wrapped.push(rest.to_string());
    }
    wrapped
}

pub(crate) fn help_page_size(width: u16, height: u16) -> usize {
    usize::from(
        help_geometry(Rect::new(0, 0, width, height))
            .height
            .saturating_sub(3),
    )
}

pub(crate) fn help_max_scroll(width: u16, height: u16) -> usize {
    let box_area = help_geometry(Rect::new(0, 0, width, height));
    help_lines(usize::from(box_area.width.saturating_sub(2)).max(1))
        .len()
        .saturating_sub(help_page_size(width, height))
}

fn help(f: &mut Frame, area: Rect, app: &App) {
    let box_area = help_geometry(area);
    let lines = help_lines(usize::from(box_area.width.saturating_sub(2)).max(1));
    let page = usize::from(box_area.height.saturating_sub(3));
    let start = app.help_scroll.min(lines.len().saturating_sub(page));
    let end = (start + page).min(lines.len());
    let mut content: Vec<TLine> = lines[start..end]
        .iter()
        .map(|line| TLine::from(Span::styled(line.clone(), Style::default().fg(muted()))))
        .collect();
    content.push(TLine::from(Span::styled(
        if box_area.width < 42 {
            "Esc/? close | ↑↓ scroll"
        } else {
            "↑↓ scroll  PgUp/PgDn page  Home/End jump  Esc/? close"
        },
        Style::default().fg(faint()),
    )));
    f.render_widget(Clear, box_area);
    f.render_widget(
        Paragraph::new(content).block(pane(&format!("keys {}/{}", end, lines.len()), true)),
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

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        format!("{s:<max$}")
    } else if max == 0 {
        // Column widths are computed from the terminal size, so a pane squeezed
        // to nothing must return empty rather than underflow the take below.
        String::new()
    } else {
        let t: String = s.chars().take(max - 1).collect();
        format!("{t}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monochrome_panes_have_square_borders_and_explicit_focus() {
        use ratatui::{buffer::Buffer, widgets::Widget};
        let area = Rect::new(0, 0, 24, 4);
        let mut active = Buffer::empty(area);
        pane("listing", true).render(area, &mut active);
        assert_eq!(active[(0, 0)].symbol(), "┌");
        assert_eq!(active[(1, 0)].symbol(), ">");
        assert_eq!(active[(1, 0)].fg, canvas());
        assert_eq!(active[(1, 0)].bg, accent());
        assert_eq!(
            active[(1, 1)].fg,
            muted(),
            "text must not inherit a light terminal's dark foreground"
        );
        let mut inactive = Buffer::empty(area);
        pane("listing", false).render(area, &mut inactive);
        assert_ne!(inactive[(1, 0)].bg, active[(1, 0)].bg);
        for color in [
            accent(),
            critical(),
            muted(),
            faint(),
            mint(),
            amber(),
            canvas(),
            panel(),
        ] {
            let Color::Rgb(r, g, b) = color else {
                panic!("expected an explicit palette color")
            };
            assert_eq!(r, g);
            assert_eq!(g, b);
        }
    }

    #[test]
    fn compact_footer_keeps_commands_and_help_visible() {
        for focus in [Focus::Functions, Focus::Listing, Focus::Xrefs] {
            for width in [40, 60, 80, 110, 160] {
                let hints = footer_hints(focus, width);
                assert!(hints.len() <= usize::from(width));
                assert!(hints.contains(": commands"));
                assert!(hints.contains("? help"));
            }
        }
        assert!(footer_hints(Focus::Functions, 160).contains("/ filter"));
        assert!(!footer_hints(Focus::Xrefs, 160).contains("/ search"));
    }

    #[test]
    fn recovered_pseudocode_types_have_the_fact_color() {
        let spans = pseudo_spans(
            "wchar_t wide; uint8_t raw; uintptr_t unknown; ptr->field_18; ptr->length;",
        );
        for ty in ["wchar_t", "uint8_t", "uintptr_t", "field_18", "length"] {
            let span = spans
                .iter()
                .find(|span| span.content.as_ref() == ty)
                .unwrap_or_else(|| panic!("missing type token {ty}"));
            assert_eq!(
                span.style.fg,
                Some(mint()),
                "{ty} should use the recovered-fact color"
            );
        }
    }
}
