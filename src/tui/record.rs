//! Deterministic demo recorder for the interactive view.
//!
//! The README's animation is not a screen capture: a capture depends on which
//! terminal, font, and console host happened to be running, and Windows
//! consoles in particular smear a redrawing TUI. Instead this drives the real
//! `App` through a scripted session, renders each step with the real `render`
//! code into an off-screen buffer, and writes the cells out. An off-line
//! rasterizer turns those cells into frames, so the picture is exactly what the
//! interface draws, at a fixed font and palette, with no capture artifacts.
//!
//! Dev-only: behind the `record` feature, so nothing here ships in the crate.
//!
//! ```text
//! cargo run --features record --bin knife-record -- TARGET scripts/demo.knife OUTDIR
//! ```

use super::{render, App};
use crate::analysis::{audit, driver};
use crate::{listing, workspace};
use anyhow::{bail, Context, Result};
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;
use std::fmt::Write as _;
use std::path::Path;

/// Default off-screen terminal size. 110x30 keeps the three panes readable at
/// a width that fits GitHub's README column.
const DEFAULT_SIZE: (u16, u16) = (110, 30);

/// One scripted action. Every step emits at least one frame, so the script
/// file also controls the pacing of the finished animation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// Resize the off-screen terminal.
    Size(u16, u16),
    /// Play the analysis splash for this many frames.
    Splash(u64),
    /// Repeat the current picture, holding it on screen.
    Hold(u32),
    /// Press a key, `n` times, one frame per press.
    Key(KeyEvent, u32),
    /// Type text one character at a time, one frame per character.
    Type(String),
}

/// Parse the demo script. The format is one command per line, `#` comments and
/// blank lines ignored:
///
/// ```text
/// size 110 30      # off-screen terminal size
/// splash 40        # play the intro for 40 frames
/// hold 12          # hold the current picture for 12 frames
/// key down 6       # press Down six times, one frame each
/// key shift+p      # modifiers: shift+, ctrl+, alt+
/// type parse_re    # type into whatever prompt is open
/// ```
fn parse_script(text: &str) -> Result<Vec<Step>> {
    let mut steps = Vec::new();
    for (no, raw) in text.lines().enumerate() {
        let line = match raw.split_once('#') {
            Some((before, _)) => before.trim(),
            None => raw.trim(),
        };
        if line.is_empty() {
            continue;
        }
        let at = no + 1;
        let (cmd, rest) = match line.split_once(char::is_whitespace) {
            Some((c, r)) => (c, r.trim()),
            None => (line, ""),
        };
        let count = |what: &str, value: &str| -> Result<u32> {
            value
                .parse::<u32>()
                .with_context(|| format!("line {at}: {what} wants a count, got {value:?}"))
        };
        steps.push(match cmd {
            "size" => {
                let (w, h) = rest
                    .split_once(char::is_whitespace)
                    .with_context(|| format!("line {at}: size wants a width and a height"))?;
                Step::Size(
                    count("size", w.trim())? as u16,
                    count("size", h.trim())? as u16,
                )
            }
            "splash" => Step::Splash(count("splash", rest)? as u64),
            "hold" | "wait" => Step::Hold(count("hold", rest)?),
            "key" => {
                let (name, times) = match rest.split_once(char::is_whitespace) {
                    Some((n, t)) => (n.trim(), count("key", t.trim())?),
                    None => (rest, 1),
                };
                Step::Key(
                    parse_key(name).with_context(|| format!("line {at}"))?,
                    times,
                )
            }
            // Deliberately not trimmed further: leading spaces can be part of
            // what is being typed into a prompt.
            "type" => Step::Type(rest.to_string()),
            other => bail!("line {at}: unknown command {other:?}"),
        });
    }
    Ok(steps)
}

/// Turn `shift+p`, `enter`, or `/` into a key event.
fn parse_key(name: &str) -> Result<KeyEvent> {
    let mut mods = KeyModifiers::NONE;
    let mut rest = name;
    while let Some((prefix, tail)) = rest.split_once('+') {
        // A bare `+` is the key itself, not a modifier separator.
        if tail.is_empty() {
            break;
        }
        match prefix {
            "shift" => mods |= KeyModifiers::SHIFT,
            "ctrl" => mods |= KeyModifiers::CONTROL,
            "alt" => mods |= KeyModifiers::ALT,
            other => bail!("unknown key modifier {other:?}"),
        }
        rest = tail;
    }
    let code = match rest {
        "enter" | "return" => KeyCode::Enter,
        "esc" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "backspace" | "bs" => KeyCode::Backspace,
        "space" => KeyCode::Char(' '),
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pgup" => KeyCode::PageUp,
        "pgdn" => KeyCode::PageDown,
        other => {
            let mut chars = other.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => KeyCode::Char(c),
                _ => bail!("unknown key {other:?}"),
            }
        }
    };
    // Crossterm reports an uppercase letter with SHIFT set; the interface reads
    // the character, so send both the way a real terminal would.
    if let (KeyCode::Char(c), true) = (code, mods.contains(KeyModifiers::SHIFT)) {
        return Ok(KeyEvent::new(KeyCode::Char(c.to_ascii_uppercase()), mods));
    }
    Ok(KeyEvent::new(code, mods))
}

/// A cell run: text that shares one style, so a row of 110 mostly-identical
/// cells is a handful of runs instead of 110 objects.
struct Run {
    text: String,
    fg: Color,
    bg: Color,
    bold: bool,
}

/// Render one buffer to JSON rows of styled runs.
fn frame_json(buffer: &ratatui::buffer::Buffer) -> String {
    let area = buffer.area;
    let cells = buffer.content();
    let mut out = String::from("{\n");
    let _ = writeln!(out, "  \"w\": {}, \"h\": {},", area.width, area.height);
    out.push_str("  \"rows\": [\n");
    for y in 0..area.height {
        let mut runs: Vec<Run> = Vec::new();
        for x in 0..area.width {
            let cell = &cells[y as usize * area.width as usize + x as usize];
            let mut fg = cell.fg;
            let mut bg = cell.bg;
            // The rasterizer knows nothing about terminal semantics, so resolve
            // reversed video here rather than teaching it the rule twice.
            if cell.modifier.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            let bold = cell.modifier.contains(Modifier::BOLD);
            let symbol = cell.symbol();
            match runs.last_mut() {
                Some(run) if run.fg == fg && run.bg == bg && run.bold == bold => {
                    run.text.push_str(symbol);
                }
                _ => runs.push(Run {
                    text: symbol.to_string(),
                    fg,
                    bg,
                    bold,
                }),
            }
        }
        let body: Vec<String> = runs
            .iter()
            .map(|r| {
                format!(
                    "[{}, \"{}\", \"{}\", {}]",
                    json_string(&r.text),
                    hex(r.fg),
                    hex(r.bg),
                    if r.bold { 1 } else { 0 }
                )
            })
            .collect();
        let comma = if y + 1 == area.height { "" } else { "," };
        let _ = writeln!(out, "    [{}]{comma}", body.join(", "));
    }
    out.push_str("  ]\n}\n");
    out
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Resolve a ratatui colour to `#rrggbb`. `Reset` becomes an empty string: the
/// rasterizer paints the theme default there, which is what a terminal does.
fn hex(color: Color) -> String {
    let (r, g, b) = match color {
        Color::Reset => return String::new(),
        Color::Rgb(r, g, b) => (r, g, b),
        Color::Black => (0x0b, 0x10, 0x16),
        Color::Red => (0xf0, 0x64, 0x64),
        Color::Green => (0x79, 0xc9, 0x9e),
        Color::Yellow => (0xe3, 0xb3, 0x41),
        Color::Blue => (0x5c, 0x8a, 0xd7),
        Color::Magenta => (0xb1, 0x7c, 0xd7),
        Color::Cyan => (0x5c, 0xc8, 0xd7),
        Color::Gray => (0xa6, 0xad, 0xbb),
        Color::DarkGray => (0x59, 0x62, 0x73),
        Color::LightRed => (0xff, 0x8a, 0x8a),
        Color::LightGreen => (0x9a, 0xe0, 0xbb),
        Color::LightYellow => (0xf2, 0xcd, 0x75),
        Color::LightBlue => (0x86, 0xac, 0xe8),
        Color::LightMagenta => (0xcb, 0x9e, 0xe8),
        Color::LightCyan => (0x8e, 0xe0, 0xea),
        Color::White => (0xe7, 0xec, 0xf2),
        // 256-colour indices are not part of the palette this interface draws
        // with; approximate rather than fail a recording over one cell.
        Color::Indexed(i) => {
            let v = 0x40u8.saturating_add(i);
            (v, v, v)
        }
    };
    format!("#{r:02x}{g:02x}{b:02x}")
}

/// Drive `target` through `script`, writing `frame-0001.json`, … into `out`.
pub fn record(target: &str, script: &Path, out: &Path) -> Result<()> {
    let text = std::fs::read_to_string(script)
        .with_context(|| format!("cannot read the script {}", script.display()))?;
    let steps = parse_script(&text)?;

    let session = workspace::Session::open(target, None, crate::ANALYSIS_BUDGET, "the recorder")?;
    let workspace::Session { bin, bytes, db, an } = session;
    let mut sinks = audit::run(&an, &bin, &bytes);
    sinks.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.reachable.cmp(&a.reachable))
            .then(a.addr.cmp(&b.addr))
    });
    let strings = listing::string_map(&bin, &bytes, crate::analysis::engine::display_base(&bin));
    let driver =
        driver::plausibly_a_driver(&bin).then(|| driver::report(&bin, &bytes, &an, &strings));
    let title = Path::new(target)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| target.to_string());
    let mut app = App::new(bin, bytes, db, an, sinks, strings, driver, title);
    app.splash = false;

    std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    // A rerun with a shorter script must not leave the tail of the last one
    // behind, or the encoder picks up frames from two different takes.
    for stale in std::fs::read_dir(out)?.flatten() {
        let path = stale.path();
        if path.extension().is_some_and(|e| e == "json") {
            let _ = std::fs::remove_file(path);
        }
    }

    let (mut w, mut h) = DEFAULT_SIZE;
    let mut term = Terminal::new(TestBackend::new(w, h))?;
    let mut written = 0usize;
    /// Draw one frame and write it out. A plain function rather than a
    /// closure: the size is rebound by `size`, which a closure capturing it
    /// would pin.
    fn shoot(
        term: &mut Terminal<TestBackend>,
        app: &mut App,
        size: (u16, u16),
        out: &Path,
        written: &mut usize,
    ) -> Result<()> {
        app.frame = app.frame.saturating_add(1);
        app.dims = size;
        term.draw(|f| render::draw(f, app))?;
        *written += 1;
        let n = *written;
        let path = out.join(format!("frame-{n:04}.json"));
        std::fs::write(&path, frame_json(term.backend().buffer()))
            .with_context(|| format!("cannot write {}", path.display()))?;
        Ok(())
    }

    for step in steps {
        match step {
            Step::Size(nw, nh) => {
                (w, h) = (nw, nh);
                term = Terminal::new(TestBackend::new(w, h))?;
            }
            Step::Splash(frames) => {
                app.splash = true;
                for _ in 0..frames {
                    shoot(&mut term, &mut app, (w, h), out, &mut written)?;
                }
                app.splash = false;
            }
            Step::Hold(frames) => {
                for _ in 0..frames {
                    shoot(&mut term, &mut app, (w, h), out, &mut written)?;
                }
            }
            Step::Key(key, times) => {
                for _ in 0..times {
                    app.on_key(key);
                    shoot(&mut term, &mut app, (w, h), out, &mut written)?;
                }
            }
            Step::Type(text) => {
                for c in text.chars() {
                    app.on_key(KeyEvent::from(KeyCode::Char(c)));
                    shoot(&mut term, &mut app, (w, h), out, &mut written)?;
                }
            }
        }
    }

    if written == 0 {
        bail!("the script produced no frames");
    }
    println!("{written} frames -> {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_parser_reads_commands_comments_and_repeats() {
        let steps = parse_script(
            "# a comment\n\nsize 90 24\nsplash 3\nkey down 4\nkey shift+p\ntype ab  # trailing\nhold 2\n",
        )
        .unwrap();
        assert_eq!(steps[0], Step::Size(90, 24));
        assert_eq!(steps[1], Step::Splash(3));
        assert_eq!(steps[2], Step::Key(KeyEvent::from(KeyCode::Down), 4));
        assert_eq!(
            steps[3],
            Step::Key(KeyEvent::new(KeyCode::Char('P'), KeyModifiers::SHIFT), 1),
            "shift uppercases the character the way crossterm reports it"
        );
        assert_eq!(steps[4], Step::Type("ab".into()));
        assert_eq!(steps[5], Step::Hold(2));
    }

    #[test]
    fn an_unknown_command_names_its_line() {
        let err = parse_script("size 90 24\nwiggle 3\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 2"), "{err}");
        assert!(err.contains("wiggle"), "{err}");
    }

    #[test]
    fn runs_merge_by_style_and_reversed_swaps_the_pair() {
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect;
        use ratatui::style::Style;
        let mut buffer = Buffer::empty(Rect::new(0, 0, 4, 1));
        let plain = Style::default()
            .fg(Color::Rgb(0x11, 0x22, 0x33))
            .bg(Color::Rgb(0x44, 0x55, 0x66));
        buffer.set_string(0, 0, "ab", plain);
        buffer.set_string(2, 0, "cd", plain.add_modifier(Modifier::REVERSED));
        let json = frame_json(&buffer);
        assert!(
            json.contains("[\"ab\", \"#112233\", \"#445566\", 0]"),
            "{json}"
        );
        assert!(
            json.contains("[\"cd\", \"#445566\", \"#112233\", 0]"),
            "reversed video is resolved before it reaches the rasterizer: {json}"
        );
    }
}
