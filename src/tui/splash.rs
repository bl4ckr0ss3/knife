//! The startup splash: a 2D ASCII knife rotating through four crisp 90-degree
//! orientations while a sparkle orbits the blade. Drawn for the first ~80
//! frames of `knife tui` and dismissed by any key.
//!
//! The animation is pure frame arithmetic: a 10x10 bitmap rotated on the fly
//! and an 8-position orbit for the sparkle, so there is no art file to keep in
//! sync and no platform quirk to worry about.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// How many frames the splash plays before the main view takes over.
pub const SPLASH_FRAMES: u64 = 80;

const CANVAS: usize = 13; // knife is 10x10, centred; the orbit needs the margin
const ART_W: usize = 37; // the fixed width the whole splash block is laid out at

/// The knife pointing up. `#` is blade and handle; the sparkle is drawn over
/// the canvas afterwards.
const BITMAP: [&str; 10] = [
    "...####...",
    "..######..",
    ".########.",
    "##########",
    "##########",
    ".########.",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
];

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

/// Rotate a square char grid 90 degrees clockwise.
fn rot90(g: &[Vec<char>]) -> Vec<Vec<char>> {
    let n = g.len();
    let mut out = vec![vec![' '; n]; n];
    for y in 0..n {
        for x in 0..n {
            out[x][n - 1 - y] = g[y][x];
        }
    }
    out
}

/// One orientation of the knife as a centred `CANVAS`x`CANVAS` grid.
fn orientation(quarter: usize) -> Vec<Vec<char>> {
    let mut g: Vec<Vec<char>> = BITMAP.iter().map(|r| r.chars().collect()).collect();
    for _ in 0..(quarter % 4) {
        g = rot90(&g);
    }
    let off = (CANVAS - BITMAP[0].len()) / 2;
    let mut canvas = vec![vec![' '; CANVAS]; CANVAS];
    for (y, row) in g.iter().enumerate() {
        for (x, &c) in row.iter().enumerate() {
            if c == '#' {
                canvas[y + off][x + off] = '#';
            }
        }
    }
    canvas
}

/// Draw one frame. The phase (0..8) drives both the quarter-turn of the knife
/// (every other phase) and the position of the sparkle on its orbit, so the
/// two motions share a clock and always agree.
///
/// While `analysing` is set the bar sweeps instead of filling (the analysis
/// has no progress callback to report) and the hint offers a quit key; once
/// the app is up it fills over the splash's remaining lifetime.
fn frame_lines(frame: u64, analysing: bool) -> Vec<TLine<'static>> {
    let phase = (frame % 8) as usize;
    let mut canvas = orientation(phase / 2);
    let a = phase as f64 * std::f64::consts::FRAC_PI_4;
    let c = (CANVAS - 1) as f64 / 2.0;
    let sx = (c + 6.0 * a.cos()).round() as usize;
    let sy = (c + 6.0 * a.sin()).round() as usize;
    if sx < CANVAS && sy < CANVAS {
        canvas[sy][sx] = '*';
    }

    let mut lines = Vec::with_capacity(17);
    for row in &canvas {
        let mut spans = Vec::new();
        let mut run = String::new();
        let mut run_style = Style::default().fg(accent());
        for &ch in row {
            let style = match ch {
                '*' => Style::default().fg(amber()).add_modifier(Modifier::BOLD),
                '#' => Style::default().fg(accent()),
                _ => Style::default(),
            };
            if style != run_style || ch == ' ' && run.is_empty() {
                if !run.is_empty() {
                    spans.push(Span::styled(std::mem::take(&mut run), run_style));
                }
                run_style = style;
            }
            run.push(ch);
        }
        if !run.is_empty() {
            spans.push(Span::styled(run, run_style));
        }
        lines.push(TLine::from(spans));
    }

    let dots = ".".repeat(1 + ((frame / 6) % 4) as usize);
    let bar_len = 22;
    let bar = if analysing {
        // An indeterminate sweep: the analysis has no progress to report.
        let mut cells = vec!['-'; bar_len];
        let pos = ((frame / 3) % (bar_len as u64 - 3)) as usize;
        for cell in cells.iter_mut().take(pos + 3).skip(pos) {
            *cell = '#';
        }
        cells.into_iter().collect()
    } else {
        let filled = ((frame * bar_len as u64) / SPLASH_FRAMES).min(bar_len as u64) as usize;
        "#".repeat(filled) + &"-".repeat(bar_len - filled)
    };
    lines.push(TLine::from(Span::styled(
        "find the bug, not just the binary",
        Style::default().fg(mint()),
    )));
    lines.push(TLine::from(Span::styled(
        format!("parsing bytes{dots}"),
        Style::default().fg(muted()),
    )));
    lines.push(TLine::from(Span::styled(
        format!("[{bar}]"),
        Style::default().fg(amber()),
    )));
    lines.push(TLine::from(Span::styled(
        if analysing {
            "analysing | press q to quit"
        } else {
            "press any key to skip"
        },
        Style::default().fg(faint()),
    )));
    lines
}

/// Render the splash, vertically and horizontally centred, in a bordered
/// block. Paragraphs clip, so a tiny terminal cannot panic the layout.
/// `frame` is the animation clock; `analysing` switches the bar and hint to
/// the pre-analysis phase.
pub fn draw(f: &mut Frame, area: Rect, frame: u64, analysing: bool) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(faint()))
        .title(Span::styled(
            " knife ",
            Style::default().fg(accent()).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);

    let lines = frame_lines(frame, analysing);
    let h = lines.len() as u16;
    let w = ART_W as u16;
    let v = Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(h),
            Constraint::Min(0),
        ])
        .split(inner);
    let hz = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Min(0),
            Constraint::Length(w),
            Constraint::Min(0),
        ])
        .split(v[1]);

    let padded: Vec<TLine> = lines
        .iter()
        .map(|l| {
            let pad = ART_W.saturating_sub(l.width()) / 2;
            let mut spans = vec![Span::raw(" ".repeat(pad))];
            spans.extend(l.spans.iter().cloned());
            TLine::from(spans)
        })
        .collect();

    f.render_widget(block, area);
    f.render_widget(Paragraph::new(padded), hz[1]);
}
