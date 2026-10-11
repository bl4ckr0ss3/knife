//! The file explorer: what a bare `knife` opens. Directories first, format
//! badges from magic bytes, and Enter hands the selected target to the
//! analysis workspace. Quitting the workspace returns here, so a triage
//! session can walk a whole samples directory without restarting.
//!
//! Like the workspace, the state machine is plain method calls so the awkward
//! parts (sorting, filtering, ascending) are tested without a terminal.

use super::render;
use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line as TLine, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// What the magic bytes say the file is, when they say anything.
    pub format: Option<&'static str>,
}

pub struct Explorer {
    pub dir: PathBuf,
    entries: Vec<Entry>,
    pub visible: Vec<usize>,
    pub selection: usize,
    pub filter: String,
    /// Whether the filter prompt at the bottom owns the keyboard.
    filtering: bool,
    pub status: String,
    pub help: bool,
    pub quit: bool,
    /// The file the user asked to open; the caller hands it to the workspace.
    pub chosen: Option<PathBuf>,
}

/// What the first bytes of a file claim it is; unknown stays unknown rather
/// than being guessed.
fn sniff_format(path: &Path) -> Option<&'static str> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).ok()?;
    let magic = &magic[..read];
    if magic.starts_with(b"MZ") {
        Some("PE")
    } else if magic.starts_with(b"\x7fELF") {
        Some("ELF")
    } else if magic.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || magic.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || magic.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || magic.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
    {
        Some("Mach-O")
    } else if magic.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || magic.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
    {
        Some("Mach-O fat")
    } else if magic.starts_with(b"!<arch>") {
        Some("archive")
    } else if magic.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
        Some("WebAssembly")
    } else {
        None
    }
}

/// Human file sizes, one decimal at most; the explorer is not the place for
/// exact byte counts.
fn format_size(size: u64) -> String {
    if size >= 1 << 20 {
        format!("{:.1}M", size as f64 / (1 << 20) as f64)
    } else if size >= 1 << 10 {
        format!("{:.1}K", size as f64 / (1 << 10) as f64)
    } else {
        format!("{size}B")
    }
}

impl Explorer {
    pub fn new(dir: &Path) -> Explorer {
        let mut explorer = Explorer {
            dir: dir.to_path_buf(),
            entries: Vec::new(),
            visible: Vec::new(),
            selection: 0,
            filter: String::new(),
            filtering: false,
            status: String::new(),
            help: false,
            quit: false,
            chosen: None,
        };
        explorer.refresh();
        explorer
    }

    /// Re-read the current directory. Returns false (and only touches the
    /// status line) when the directory cannot be read.
    fn refresh(&mut self) -> bool {
        let read = match std::fs::read_dir(&self.dir) {
            Ok(read) => read,
            Err(error) => {
                self.status = format!("cannot read {}: {error}", self.dir.display());
                self.entries.clear();
                self.visible.clear();
                self.selection = 0;
                return false;
            }
        };
        let mut entries: Vec<Entry> = read
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let metadata = entry.metadata().ok()?;
                let is_dir = metadata.is_dir();
                Some(Entry {
                    name: entry.file_name().to_string_lossy().to_string(),
                    is_dir,
                    size: if is_dir { 0 } else { metadata.len() },
                    format: if is_dir {
                        None
                    } else {
                        sniff_format(&entry.path())
                    },
                })
            })
            .collect();
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        self.entries = entries;
        self.apply_filter();
        true
    }

    fn apply_filter(&mut self) {
        let keep = self.selected().map(|entry| entry.name.clone());
        let needle = self.filter.to_lowercase();
        self.visible = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| needle.is_empty() || entry.name.to_lowercase().contains(&needle))
            .map(|(index, _)| index)
            .collect();
        self.selection = keep
            .and_then(|name| {
                self.visible
                    .iter()
                    .position(|&index| self.entries[index].name == name)
            })
            .unwrap_or(0);
    }

    pub fn selected(&self) -> Option<&Entry> {
        self.visible
            .get(self.selection)
            .and_then(|&index| self.entries.get(index))
    }

    pub fn step(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let last = self.visible.len() - 1;
        self.selection = self.selection.saturating_add_signed(delta).min(last);
    }

    /// Enter the selected directory, or hand the selected file to the caller.
    pub fn activate(&mut self) {
        let Some(entry) = self.selected().cloned() else {
            return;
        };
        if entry.is_dir {
            let target = self.dir.join(&entry.name);
            match std::fs::read_dir(&target) {
                Ok(_) => {
                    self.dir = target;
                    self.filter.clear();
                    self.refresh();
                    self.selection = 0;
                    self.status.clear();
                }
                Err(error) => {
                    self.status = format!("cannot open {}: {error}", target.display());
                }
            }
        } else {
            self.chosen = Some(self.dir.join(&entry.name));
        }
    }

    pub fn ascend(&mut self) {
        let parent = self.dir.parent().map(|parent| parent.to_path_buf());
        match parent {
            Some(parent) => {
                let previous = std::mem::replace(&mut self.dir, parent);
                self.filter.clear();
                self.refresh();
                // Land on the directory we just came out of.
                if let Some(name) = previous
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                {
                    if let Some(position) = self
                        .visible
                        .iter()
                        .position(|&index| self.entries[index].name == name)
                    {
                        self.selection = position;
                    }
                }
            }
            None => self.status = "at the filesystem root".into(),
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.kind != KeyEventKind::Press {
            return; // Windows reports releases too; acting on both double-fires
        }
        if self.help {
            self.help = false;
            return;
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.apply_filter();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.apply_filter();
                }
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Esc => {
                if self.filter.is_empty() {
                    self.quit = true;
                } else {
                    self.filter.clear();
                    self.apply_filter();
                }
            }
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('/') => self.filtering = true,
            KeyCode::Down | KeyCode::Char('j') => self.step(1),
            KeyCode::Up | KeyCode::Char('k') => self.step(-1),
            KeyCode::PageDown => self.step(10),
            KeyCode::PageUp => self.step(-10),
            KeyCode::Home => self.step(isize::MIN / 2),
            KeyCode::End => self.step(isize::MAX / 2),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => self.activate(),
            KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => self.ascend(),
            _ => {}
        }
    }
}

/// Pick a target, or nothing when the user quits. The terminal is restored
/// before returning so the workspace can take it over next.
pub fn run(start: &Path) -> Result<Option<PathBuf>> {
    let mut term =
        ratatui::try_init().map_err(|e| anyhow::anyhow!("cannot start the explorer: {e}"))?;
    let mut explorer = Explorer::new(start);
    let res = loop {
        if let Err(e) = term.draw(|f| draw(f, &explorer)) {
            break Err(anyhow::Error::from(e));
        }
        match event::read() {
            Ok(Event::Key(k)) => explorer.on_key(k),
            Ok(_) => {}
            Err(e) => break Err(anyhow::Error::from(e)),
        }
        if let Some(path) = explorer.chosen.take() {
            break Ok(Some(path));
        }
        if explorer.quit {
            break Ok(None);
        }
    };
    ratatui::restore();
    res
}

fn draw(f: &mut Frame, explorer: &Explorer) {
    let area = f.area();
    f.render_widget(
        Paragraph::new("").style(Style::default().bg(render::canvas())),
        area,
    );
    if area.width < 24 || area.height < 6 {
        f.render_widget(
            Paragraph::new("KNIFE\n\nterminal too small; resize the window")
                .style(Style::default().fg(render::muted()).bg(render::canvas()))
                .wrap(ratatui::widgets::Wrap { trim: true }),
            area,
        );
        return;
    }
    use ratatui::layout::{Constraint, Direction, Layout};
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(area);

    let header = TLine::from(vec![
        Span::styled(
            " KNIFE  explorer ",
            Style::default()
                .fg(render::accent())
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" │  {}", explorer.dir.display()),
            Style::default().fg(render::faint()),
        ),
    ]);
    f.render_widget(Paragraph::new(header), rows[0]);

    let title = if explorer.filter.is_empty() {
        format!("{} entries", explorer.visible.len())
    } else {
        format!("{} entries /{}", explorer.visible.len(), explorer.filter)
    };
    let items: Vec<ListItem> = if explorer.visible.is_empty() {
        vec![ListItem::new(TLine::from(Span::styled(
            " (nothing here)",
            Style::default().fg(render::faint()),
        )))]
    } else {
        explorer
            .visible
            .iter()
            .map(|&index| {
                let entry = &explorer.entries[index];
                let (badge, label, color) = if entry.is_dir {
                    (
                        "dir  ".to_string(),
                        format!("{}/", entry.name),
                        render::mint(),
                    )
                } else {
                    (
                        format!("{:<5}", entry.format.unwrap_or("")),
                        entry.name.clone(),
                        if entry.format.is_some() {
                            render::accent()
                        } else {
                            render::muted()
                        },
                    )
                };
                let name = render::truncate(&label, usize::from(area.width.saturating_sub(20)));
                ListItem::new(TLine::from(vec![
                    Span::styled(badge, Style::default().fg(render::faint())),
                    Span::styled(name, Style::default().fg(color)),
                    Span::styled(
                        if entry.is_dir {
                            String::new()
                        } else {
                            format!("  {}", format_size(entry.size))
                        },
                        Style::default().fg(render::faint()),
                    ),
                ]))
            })
            .collect()
    };
    let mut state = ListState::default();
    if !explorer.visible.is_empty() {
        state.select(Some(explorer.selection));
    }
    f.render_stateful_widget(
        List::new(items)
            .block(render::pane(&title, true))
            .highlight_style(render::selected())
            .highlight_symbol("▸"),
        rows[1],
        &mut state,
    );

    if explorer.filtering {
        let line = TLine::from(vec![
            Span::styled(
                " filter: ",
                Style::default()
                    .fg(render::accent())
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(explorer.filter.clone()),
            Span::styled("█", Style::default().fg(render::accent())),
        ]);
        f.render_widget(Paragraph::new(line), rows[2]);
    } else if !explorer.status.is_empty() {
        f.render_widget(
            Paragraph::new(TLine::from(Span::styled(
                format!(" {}", explorer.status),
                Style::default().fg(render::amber()),
            ))),
            rows[2],
        );
    } else {
        f.render_widget(
            Paragraph::new(TLine::from(Span::styled(
                " Enter open │ / filter │ Backspace up │ ? help │ q quit",
                Style::default().fg(render::muted()),
            ))),
            rows[2],
        );
    }

    if explorer.help {
        let text = vec![
            "",
            "  ↑ ↓ / j k    move            Enter    open directory or target",
            "  Backspace    up a directory  /        filter by name",
            "  Esc          clear the filter, then quit",
            "  q            quit",
            "",
            "  PE, ELF, Mach-O and archives carry a badge; opening a target",
            "  starts the analysis workspace, and quitting it returns here.",
            "",
            "  any key to dismiss",
        ];
        let w = 68u16.min(area.width.saturating_sub(4));
        let h = (text.len() as u16 + 2).min(area.height);
        let box_area = ratatui::layout::Rect {
            x: area.x + (area.width.saturating_sub(w)) / 2,
            y: area.y + (area.height.saturating_sub(h)) / 2,
            width: w,
            height: h,
        };
        f.render_widget(ratatui::widgets::Clear, box_area);
        f.render_widget(
            Paragraph::new(
                text.into_iter()
                    .map(|l| TLine::from(Span::styled(l, Style::default().fg(render::muted()))))
                    .collect::<Vec<_>>(),
            )
            .block(render::pane("help", true)),
            box_area,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sample directory: one subdirectory, one PE, one ELF, one text file.
    fn sample_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("knife-explorer-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sample.exe"), b"MZ\0\0 fake pe body").unwrap();
        std::fs::write(dir.join("daemon"), b"\x7fELF\x02\x01\x01\0 fake elf").unwrap();
        std::fs::write(dir.join("notes.txt"), b"plain text").unwrap();
        dir
    }

    #[test]
    fn directories_sort_first_and_formats_are_sniffed() {
        let dir = sample_dir("sort");
        let explorer = Explorer::new(&dir);
        let names: Vec<&str> = explorer
            .visible
            .iter()
            .map(|&i| explorer.entries[i].name.as_str())
            .collect();
        assert_eq!(names, ["sub", "daemon", "notes.txt", "sample.exe"]);
        let entry = |name: &str| explorer.entries.iter().find(|e| e.name == name).unwrap();
        assert_eq!(entry("sample.exe").format, Some("PE"));
        assert_eq!(entry("daemon").format, Some("ELF"));
        assert_eq!(entry("notes.txt").format, None);
        assert!(entry("sub").is_dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entering_a_directory_lands_back_on_it_when_ascending() {
        let dir = sample_dir("walk");
        let mut explorer = Explorer::new(&dir);
        assert_eq!(explorer.selected().unwrap().name, "sub");
        explorer.activate();
        assert_eq!(explorer.dir, dir.join("sub"));
        explorer.ascend();
        assert_eq!(explorer.dir, dir);
        assert_eq!(explorer.selected().unwrap().name, "sub");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn selecting_a_file_chooses_it_for_the_workspace() {
        let dir = sample_dir("pick");
        let mut explorer = Explorer::new(&dir);
        // daemon is the second row after the directory.
        explorer.step(1);
        explorer.activate();
        assert_eq!(explorer.chosen, Some(dir.join("daemon")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn filtering_keeps_the_selection_when_it_survives() {
        let dir = sample_dir("filter");
        let mut explorer = Explorer::new(&dir);
        explorer.step(3);
        assert_eq!(explorer.selected().unwrap().name, "sample.exe");
        explorer.filter = "sam".into();
        explorer.apply_filter();
        assert_eq!(explorer.visible.len(), 1);
        assert_eq!(explorer.selected().unwrap().name, "sample.exe");
        explorer.filter = "absent".into();
        explorer.apply_filter();
        assert!(explorer.visible.is_empty());
        assert!(explorer.selected().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn esc_clears_the_filter_before_quitting() {
        let dir = sample_dir("esc");
        let mut explorer = Explorer::new(&dir);
        explorer.filter = "sam".into();
        explorer.apply_filter();
        explorer.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(!explorer.quit, "the first Esc only clears the filter");
        assert!(explorer.filter.is_empty());
        explorer.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(explorer.quit);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_explorer_renders() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let dir = sample_dir("render");
        let explorer = Explorer::new(&dir);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| draw(f, &explorer)).unwrap();
        let out: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(out.contains("KNIFE"), "the brand header is drawn");
        assert!(out.contains("sample.exe"), "targets are listed");
        assert!(out.contains("PE"), "the format badge is drawn");
        assert!(out.contains("? help"), "help stays discoverable");
        std::fs::remove_dir_all(&dir).ok();
    }
}
