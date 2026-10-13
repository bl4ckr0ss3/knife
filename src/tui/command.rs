//! Local workstation commands. Input is never executed as a shell command.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Investigation,
    Contradictions,
    RefreshInvestigation,
    Ask(String),
    RunTool(String),
    InterruptInvestigation,
    Goto(String),
    Function(String),
    Functions,
    Catalog(super::browser::Catalog),
    Types,
    Xrefs,
    Callers,
    Callees,
    Cfg,
    Decompile,
    Disasm,
    Rename(String),
    Comment(String),
    Bookmark,
    Search(String),
    Back,
    Forward,
    NextFunction,
    PreviousFunction,
    Focus(super::Focus),
    Close,
    Widen,
    Narrow,
    Zoom,
    Reload,
    Split,
    Only,
    Compare(Option<String>),
    Help,
    Quit,
}

pub const NAMES: &[&str] = &[
    "investigation",
    "contradictions",
    "investigation-reload",
    "ask",
    "run-tool",
    "interrupt",
    "goto",
    "function",
    "functions",
    "imports",
    "exports",
    "strings",
    "sections",
    "headers",
    "segments",
    "section-headers",
    "types",
    "xrefs",
    "callers",
    "callees",
    "cfg",
    "decompile",
    "disasm",
    "rename",
    "comment",
    "bookmark",
    "bookmarks",
    "search",
    "back",
    "forward",
    "next",
    "previous",
    "history",
    "focus",
    "close",
    "widen",
    "narrow",
    "zoom",
    "reload",
    "split",
    "only",
    "compare",
    "help",
    "quit",
];

impl super::App {
    pub fn execute_command(&mut self, input: &str) {
        use super::{Ask, Focus, LeftView, RefView};
        let command = match parse(input) {
            Ok(command) => command,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        match command {
            Command::Investigation => {
                self.investigation_open = true;
                self.investigation_conflicts_only = false;
            }
            Command::Contradictions => {
                self.investigation_open = true;
                self.investigation_conflicts_only = true;
            }
            Command::RefreshInvestigation => self.refresh_investigation(),
            Command::Ask(question) => self.investigation_question(question),
            Command::RunTool(input) => self.run_investigation_tool(&input),
            Command::InterruptInvestigation => {
                if let Some(token) = self.investigation_cancellation.take() {
                    token.cancel();
                }
                self.investigation_worker = None;
                self.investigation_live_activity = None;
                self.investigation_activity =
                    "Interrupted: pending result discarded; provider cleanup may still be running"
                        .into();
            }
            Command::Goto(selector) => {
                self.commit_with_context(Ask::Goto, 0, selector, None, None);
                self.focus = Focus::Listing;
            }
            Command::Function(selector) => {
                match crate::api::navigation::resolve_function_in(&self.an, &selector)
                    .map(|function| function.addr)
                {
                    Some(address) => {
                        self.open(address, true);
                        self.focus = Focus::Listing;
                    }
                    None => {
                        self.status = format!(
                            "no unique recovered function matches '{selector}'; use a static VA"
                        )
                    }
                }
            }
            Command::Functions => {
                self.browser = None;
                self.left = LeftView::Functions;
                self.focus = Focus::Functions;
            }
            Command::Types => {
                self.browser = None;
                self.left = LeftView::Types;
                self.focus = Focus::Functions;
            }
            Command::Xrefs | Command::Callers | Command::Callees if self.split => {
                self.status = "references are hidden while split; :only closes a pane".into();
            }
            Command::Xrefs => {
                self.reference_anchor = Some(self.xref_at());
                self.refview = RefView::To;
                self.focus = Focus::Xrefs;
                self.clamp_xsel();
            }
            Command::Callers | Command::Callees => {
                self.refview = if command == Command::Callers {
                    RefView::Callers
                } else {
                    RefView::From
                };
                self.focus = Focus::Xrefs;
                self.xsel = 0;
                self.clamp_xsel();
            }
            Command::Cfg => {
                if !self.graph {
                    self.toggle_graph();
                }
                self.focus = Focus::Listing;
            }
            Command::Decompile => {
                if !self.pseudo {
                    self.toggle_pseudo();
                }
                self.focus = Focus::Listing;
            }
            Command::Disasm => {
                if self.graph {
                    self.toggle_graph();
                }
                if self.pseudo {
                    self.toggle_pseudo();
                }
                self.focus = Focus::Listing;
            }
            Command::Rename(name) => {
                if let Some(address) = self.current_function().map(|function| function.addr) {
                    self.commit_with_context(Ask::Name, address, name, None, None);
                } else {
                    self.status = "open a recovered function before renaming it".into();
                }
            }
            Command::Comment(text) => {
                if self.raw_file {
                    self.status = "raw file offsets cannot be annotated as image addresses".into();
                    return;
                }
                if let Some(address) = self.cursor_addr().or(self.cur) {
                    self.commit_with_context(Ask::Note, address, text, None, None);
                } else {
                    self.status = "select an address before commenting".into();
                }
            }
            Command::Search(text) => self.search_listing(text),
            Command::Bookmark => {
                if self.raw_file {
                    self.status = "raw file offsets cannot be bookmarked as image addresses".into();
                    return;
                }
                let Some(address) = self.cursor_addr().or(self.cur) else {
                    self.status = "select an address before bookmarking".into();
                    return;
                };
                let enabled = address
                    .checked_sub(self.base)
                    .is_none_or(|offset| !self.db.bookmarks.contains(&offset));
                match crate::api::bookmarks::set(
                    &self.bin,
                    &mut self.db,
                    crate::address::StaticVa(address),
                    enabled,
                ) {
                    Ok(()) => {
                        self.refresh_catalog();
                        self.status = format!(
                            "{} bookmark at static VA 0x{address:x}",
                            if enabled { "added" } else { "removed" }
                        );
                    }
                    Err(error) => self.status = format!("bookmark was not saved: {error:#}"),
                }
            }
            Command::Back => self.back(),
            Command::Focus(Focus::Xrefs) if self.split => {
                self.status = "references are hidden while split; :only closes a pane".into();
            }
            Command::Focus(focus) => self.focus = focus,
            Command::Close => self.close_pane(),
            Command::Widen => self.resize_pane(4),
            Command::Narrow => self.resize_pane(-4),
            Command::Zoom => self.toggle_pane_zoom(),
            Command::Forward => self.forward(),
            Command::NextFunction | Command::PreviousFunction => {
                let forward = command == Command::NextFunction;
                let address = self.cur.unwrap_or(0);
                match crate::api::navigation::adjacent_function(
                    &self.an,
                    crate::address::StaticVa(address),
                    forward,
                ) {
                    Some(address) => {
                        self.open(address.get(), true);
                        self.focus = Focus::Listing;
                    }
                    None => {
                        self.status = if forward {
                            "no next recovered function"
                        } else {
                            "no previous recovered function"
                        }
                        .into()
                    }
                }
            }
            Command::Catalog(catalog) => self.show_catalog(catalog),
            Command::Reload => self.reload(),
            Command::Split => self.split_clone(),
            Command::Only => self.close_split(),
            Command::Compare(selector) => self.compare(selector),
            Command::Help => self.help = true,
            Command::Quit => self.quit = true,
        }
    }
}

pub fn parse(input: &str) -> Result<Command, String> {
    let input = input.trim().strip_prefix(':').unwrap_or(input.trim());
    let (verb, rest) = input.split_once(char::is_whitespace).unwrap_or((input, ""));
    let rest = rest.trim();
    let required = || {
        if rest.is_empty() {
            Err(format!("{verb} requires an argument"))
        } else {
            Ok(rest.to_owned())
        }
    };
    let no_args = |command| {
        if rest.is_empty() {
            Ok(command)
        } else {
            Err(format!("{verb} does not accept arguments"))
        }
    };
    match verb {
        "investigation" => no_args(Command::Investigation),
        "contradictions" => no_args(Command::Contradictions),
        "investigation-reload" => no_args(Command::RefreshInvestigation),
        "ask" => required().map(Command::Ask),
        "run-tool" => required().map(Command::RunTool),
        "interrupt" => no_args(Command::InterruptInvestigation),
        "goto" => required().map(Command::Goto),
        "function" => required().map(Command::Function),
        "rename" => required().map(Command::Rename),
        "comment" => required().map(Command::Comment),
        "search" => required().map(Command::Search),
        "functions" => no_args(Command::Functions),
        "sections" => no_args(Command::Catalog(super::browser::Catalog::Sections)),
        "headers" => no_args(Command::Catalog(super::browser::Catalog::ElfHeaders)),
        "segments" => no_args(Command::Catalog(super::browser::Catalog::ElfSegments)),
        "section-headers" => no_args(Command::Catalog(super::browser::Catalog::ElfSectionHeaders)),
        "bookmark" => no_args(Command::Bookmark),
        "bookmarks" => no_args(Command::Catalog(super::browser::Catalog::Bookmarks)),
        "imports" => no_args(Command::Catalog(super::browser::Catalog::Imports)),
        "exports" => no_args(Command::Catalog(super::browser::Catalog::Exports)),
        "strings" => no_args(Command::Catalog(super::browser::Catalog::Strings)),
        "types" => no_args(Command::Types),
        "xrefs" => no_args(Command::Xrefs),
        "callers" => no_args(Command::Callers),
        "callees" => no_args(Command::Callees),
        "cfg" => no_args(Command::Cfg),
        "decompile" => no_args(Command::Decompile),
        "disasm" => no_args(Command::Disasm),
        "back" => no_args(Command::Back),
        "forward" => no_args(Command::Forward),
        "next" => no_args(Command::NextFunction),
        "previous" => no_args(Command::PreviousFunction),
        "history" => no_args(Command::Catalog(super::browser::Catalog::History)),
        "close" => no_args(Command::Close),
        "widen" => no_args(Command::Widen),
        "narrow" => no_args(Command::Narrow),
        "zoom" => no_args(Command::Zoom),
        "reload" => no_args(Command::Reload),
        "split" => no_args(Command::Split),
        "only" => no_args(Command::Only),
        "compare" => Ok(Command::Compare(if rest.is_empty() {
            None
        } else {
            Some(rest.to_owned())
        })),
        "focus" => match rest {
            "functions" => Ok(Command::Focus(super::Focus::Functions)),
            "listing" => Ok(Command::Focus(super::Focus::Listing)),
            "references" => Ok(Command::Focus(super::Focus::Xrefs)),
            _ => Err("focus requires functions, listing, or references".into()),
        },
        "help" => no_args(Command::Help),
        "quit" => no_args(Command::Quit),
        "" => Err("Enter a command; use help for keybindings".into()),
        _ => Err(format!("unknown command '{verb}'; use help")),
    }
}

/// Complete a verb only. Arguments and binary data never become commands.
pub fn complete(input: &str) -> Vec<&'static str> {
    if input.chars().any(char::is_whitespace) {
        return Vec::new();
    }
    NAMES
        .iter()
        .copied()
        .filter(|name| name.starts_with(input))
        .collect()
}

#[derive(Debug, Default)]
pub struct History {
    entries: Vec<String>,
    cursor: Option<usize>,
    draft: String,
}

impl History {
    pub fn record(&mut self, input: &str) {
        if !input.trim().is_empty() && self.entries.last().map(String::as_str) != Some(input) {
            self.entries.push(input.to_owned());
            if self.entries.len() > 200 {
                self.entries.remove(0);
            }
        }
        self.reset();
    }

    pub fn reset(&mut self) {
        self.cursor = None;
        self.draft.clear();
    }

    pub fn previous(&mut self, current: &str) -> String {
        if self.entries.is_empty() {
            return current.to_owned();
        }
        let index = match self.cursor {
            Some(index) => index.saturating_sub(1),
            None => {
                self.draft = current.to_owned();
                self.entries.len() - 1
            }
        };
        self.cursor = Some(index);
        self.entries[index].clone()
    }

    pub fn next(&mut self, current: &str) -> String {
        match self.cursor {
            Some(index) if index + 1 < self.entries.len() => {
                self.cursor = Some(index + 1);
                self.entries[index + 1].clone()
            }
            Some(_) => {
                self.cursor = None;
                self.draft.clone()
            }
            None => current.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_commands_parse_with_and_without_arguments() {
        assert_eq!(parse("split").unwrap(), Command::Split);
        assert_eq!(parse("only").unwrap(), Command::Only);
        assert_eq!(parse("compare").unwrap(), Command::Compare(None));
        assert_eq!(
            parse("compare main").unwrap(),
            Command::Compare(Some("main".into()))
        );
        assert!(parse("split now").is_err());
        assert!(complete("spl").contains(&"split"));
        assert_eq!(parse("zoom").unwrap(), Command::Zoom);
        assert!(parse("zoom now").is_err());
    }

    #[test]
    fn commands_preserve_text_and_reject_invalid_shapes() {
        assert_eq!(
            parse(":comment check length < capacity"),
            Ok(Command::Comment("check length < capacity".into()))
        );
        assert_eq!(
            parse("function operator new"),
            Ok(Command::Function("operator new".into()))
        );
        assert!(parse("goto").is_err());
        assert!(parse("cfg garbage").is_err());
        assert_eq!(parse(":callers"), Ok(Command::Callers));
        assert!(parse("callers garbage").is_err());
        assert!(parse("!powershell").is_err());
        assert!(parse("").is_err());
        assert_eq!(complete("de"), vec!["decompile"]);
        assert!(complete("goto de").is_empty());
        assert_eq!(
            parse("headers"),
            Ok(Command::Catalog(super::super::browser::Catalog::ElfHeaders))
        );
        assert_eq!(
            parse("segments"),
            Ok(Command::Catalog(
                super::super::browser::Catalog::ElfSegments
            ))
        );
        assert_eq!(
            parse("section-headers"),
            Ok(Command::Catalog(
                super::super::browser::Catalog::ElfSectionHeaders
            ))
        );
    }

    #[test]
    fn history_restores_draft_and_has_a_bound() {
        let mut history = History::default();
        history.record("cfg");
        history.record("disasm");
        history.record("disasm");
        assert_eq!(history.previous("unfinished"), "disasm");
        assert_eq!(history.previous("disasm"), "cfg");
        assert_eq!(history.next("cfg"), "disasm");
        assert_eq!(history.next("disasm"), "unfinished");
        for index in 0..250 {
            history.record(&format!("goto {index:x}"));
        }
        assert_eq!(history.entries.len(), 200);
    }
}
