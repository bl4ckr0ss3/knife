//! One geometry model for rendering and hit testing.
use super::{App, Focus, LeftView};
use ratatui::layout::{Constraint, Direction, Layout, Rect};

#[derive(Debug, Clone)]
pub struct PaneSettings {
    pub functions: bool,
    pub references: bool,
    pub left_width: u16,
    pub reference_width: u16,
    pub zoom: Option<Focus>,
}

impl Default for PaneSettings {
    fn default() -> Self {
        Self {
            functions: true,
            references: true,
            left_width: 38,
            reference_width: 32,
            zoom: None,
        }
    }
}

pub struct Panes {
    pub header: Rect,
    pub footer: Rect,
    pub functions: Rect,
    pub listing: Rect,
    /// The second listing column in split mode; a zero rect otherwise.
    pub listing_right: Rect,
    pub references: Rect,
    pub detail: Rect,
}

impl App {
    pub fn panes(&self, area: Rect) -> Panes {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .split(area);
        if self.pane_settings.zoom.is_some() {
            // Focus changes while zoomed (Tab, mouse, or :focus) switch the
            // maximized pane instead of leaving focus on an invisible pane.
            let zoom = self.focus;
            let content = rows[1];
            return Panes {
                header: rows[0],
                footer: rows[2],
                functions: if zoom == Focus::Functions {
                    content
                } else {
                    Rect::default()
                },
                listing: if zoom == Focus::Listing {
                    content
                } else {
                    Rect::default()
                },
                listing_right: Rect::default(),
                references: if zoom == Focus::Xrefs && !self.split {
                    content
                } else {
                    Rect::default()
                },
                detail: Rect::default(),
            };
        }
        let left = self.pane_settings.functions || self.focus == Focus::Functions;
        let detail_height = match self.left {
            LeftView::Sinks if !self.sinks.is_empty() => 6,
            LeftView::Types => 7,
            _ => 0,
        };
        let left_width = if left {
            self.pane_settings.left_width.min(area.width / 2)
        } else {
            0
        };
        // Split mode: the references pane's slot becomes the second listing,
        // so the two columns always sit side by side regardless of width.
        if self.split {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(left_width),
                    Constraint::Min(1),
                    Constraint::Min(1),
                ])
                .split(rows[1]);
            let center = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(detail_height)])
                .split(cols[1]);
            return Panes {
                header: rows[0],
                footer: rows[2],
                functions: cols[0],
                listing: center[0],
                listing_right: cols[2],
                references: Rect::default(),
                detail: center[1],
            };
        }
        // An empty reference pane is noise, especially in raw-file views.
        // Keep it collapsed until it has rows or the user focuses it.
        let refs = (self.pane_settings.references && !self.xref_rows().is_empty())
            || self.focus == Focus::Xrefs;
        let wide = area.width >= 132;
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(left_width),
                Constraint::Min(1),
                Constraint::Length(if refs && wide {
                    self.pane_settings.reference_width.min(area.width / 3)
                } else {
                    0
                }),
            ])
            .split(rows[1]);
        let center = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(detail_height),
                Constraint::Length(if refs && !wide { 8 } else { 0 }),
            ])
            .split(cols[1]);
        Panes {
            header: rows[0],
            footer: rows[2],
            functions: cols[0],
            listing: center[0],
            listing_right: Rect::default(),
            detail: center[1],
            references: if wide { cols[2] } else { center[2] },
        }
    }

    pub fn close_pane(&mut self) {
        self.pane_settings.zoom = None;
        match self.focus {
            Focus::Functions => self.pane_settings.functions = false,
            Focus::Xrefs => self.pane_settings.references = false,
            Focus::Listing => {
                if self.split {
                    // Closing the focused column keeps the other one.
                    self.close_split();
                    return;
                }
                self.status = "listing stays open; focus a side pane to close it".into();
                return;
            }
        }
        self.focus = Focus::Listing;
    }

    pub fn resize_pane(&mut self, delta: i16) {
        let applied = match self.focus {
            Focus::Functions => {
                self.pane_settings.left_width = self
                    .pane_settings
                    .left_width
                    .saturating_add_signed(delta)
                    .clamp(20, 80);
                self.pane_settings.left_width
            }
            Focus::Xrefs => {
                self.pane_settings.reference_width = self
                    .pane_settings
                    .reference_width
                    .saturating_add_signed(delta)
                    .clamp(20, 80);
                self.pane_settings.reference_width
            }
            Focus::Listing => {
                // Growing the center means taking equal space from the side
                // panes; shrinking it returns space to both.
                let side_delta = delta.saturating_neg();
                if self.pane_settings.functions {
                    self.pane_settings.left_width = self
                        .pane_settings
                        .left_width
                        .saturating_add_signed(side_delta)
                        .clamp(20, 80);
                }
                if self.pane_settings.references {
                    self.pane_settings.reference_width = self
                        .pane_settings
                        .reference_width
                        .saturating_add_signed(side_delta)
                        .clamp(20, 80);
                }
                0
            }
        };
        self.status = if self.focus == Focus::Listing {
            "listing width updated by resizing visible side panes".into()
        } else {
            format!("focused pane width: {applied} columns")
        };
    }

    pub fn toggle_pane_zoom(&mut self) {
        if self.pane_settings.zoom.is_some() {
            self.pane_settings.zoom = None;
            self.status = "restored pane layout".into();
            return;
        }
        if self.focus == Focus::Xrefs && self.split {
            self.status = "references are unavailable while listings are split".into();
            return;
        }
        self.pane_settings.zoom = Some(self.focus);
        self.status = "focused pane maximized; z restores the layout".into();
    }
}
