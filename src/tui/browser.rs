//! Cached presentation rows from shared deterministic catalog queries.
use crate::address::{FileOffset, StaticVa};
use crate::api::{listing, symbols};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Catalog {
    Imports,
    Exports,
    Strings,
    Bookmarks,
    Sections,
    ElfHeaders,
    ElfSegments,
    ElfSectionHeaders,
    History,
}

impl Catalog {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::Exports => "exports",
            Self::Strings => "strings",
            Self::Bookmarks => "bookmarks",
            Self::Sections => "sections",
            Self::ElfHeaders => "ELF header",
            Self::ElfSegments => "ELF segments",
            Self::ElfSectionHeaders => "ELF section headers",
            Self::History => "navigation history",
        }
    }

    pub const fn is_elf_structure(self) -> bool {
        matches!(
            self,
            Self::ElfHeaders | Self::ElfSegments | Self::ElfSectionHeaders
        )
    }
}

pub struct Row {
    pub address: Option<StaticVa>,
    pub file_offset: Option<FileOffset>,
    pub label: String,
    pub detail: String,
    pub record_offset: Option<FileOffset>,
    search_text: String,
    navigation: Option<super::NavigationLocation>,
}

impl Row {
    fn new(
        address: Option<StaticVa>,
        file_offset: Option<FileOffset>,
        label: String,
        detail: String,
    ) -> Self {
        let search_text = format!("{label} {detail}").to_lowercase();
        Self {
            address,
            file_offset,
            label,
            detail,
            record_offset: None,
            search_text,
            navigation: None,
        }
    }
}

pub struct Browser {
    pub catalog: Catalog,
    pub rows: Vec<Row>,
    pub visible: Vec<usize>,
    pub selection: usize,
    pub filter: String,
}

impl Browser {
    pub fn selected(&self) -> Option<&Row> {
        self.visible
            .get(self.selection)
            .and_then(|index| self.rows.get(*index))
    }

    pub fn filter(&mut self, text: String) {
        let keep = self.visible.get(self.selection).copied();
        let needle = text.to_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| row.search_text.contains(&needle))
            .map(|(index, _)| index)
            .collect();
        self.selection = keep
            .and_then(|index| self.visible.iter().position(|item| *item == index))
            .unwrap_or(0);
        self.filter = text;
    }

    pub fn step(&mut self, delta: isize) {
        self.selection = self
            .selection
            .saturating_add_signed(delta)
            .min(self.visible.len().saturating_sub(1));
    }
}

impl super::App {
    pub fn refresh_catalog(&mut self) {
        let Some(browser) = &self.browser else {
            return;
        };
        let catalog = browser.catalog;
        let filter = browser.filter.clone();
        let address = browser.selected().and_then(|row| row.address);
        let file_offset = browser.selected().and_then(|row| row.file_offset);
        let focus = self.focus;
        let status = self.status.clone();
        self.show_catalog(catalog);
        if let Some(browser) = &mut self.browser {
            browser.filter(filter);
            if let Some(address) = address {
                if let Some(index) = browser
                    .visible
                    .iter()
                    .position(|index| browser.rows[*index].address == Some(address))
                {
                    browser.selection = index;
                }
            } else if let Some(file_offset) = file_offset {
                if let Some(index) = browser
                    .visible
                    .iter()
                    .position(|index| browser.rows[*index].file_offset == Some(file_offset))
                {
                    browser.selection = index;
                }
            }
        }
        self.focus = focus;
        self.status = status;
    }

    pub fn show_catalog(&mut self, catalog: Catalog) {
        let rows = match catalog {
            Catalog::History => self
                .history
                .iter()
                .rev()
                .map(|location| ("PAST", location))
                .chain(
                    self.future
                        .iter()
                        .rev()
                        .map(|location| ("FORWARD", location)),
                )
                .map(|(direction, location)| {
                    let address = (!location.file_offset).then_some(StaticVa(location.address));
                    let file_offset = location.file_offset.then_some(FileOffset(location.address));
                    let mut row = Row::new(
                        address,
                        file_offset,
                        if location.file_offset {
                            format!("OFF 0x{:x}", location.address)
                        } else {
                            self.an.label(location.address)
                        },
                        format!(
                            "{direction} {} row {}",
                            if location.file_offset {
                                "RAW FILE"
                            } else if location.graph {
                                "CFG"
                            } else if location.pseudo {
                                "PSEUDOCODE"
                            } else {
                                "DISASSEMBLY"
                            },
                            location.cursor + 1
                        ),
                    );
                    row.navigation = Some(location.clone());
                    row
                })
                .collect(),
            Catalog::Sections => crate::api::binary_summary::sections(&self.bin)
                .into_iter()
                .map(|section| {
                    let native_address = match section.address {
                        crate::api::binary_summary::ImageAddress::Rva(address) => {
                            format!("RVA {:x}", address.get())
                        }
                        crate::api::binary_summary::ImageAddress::StaticVa(address) => {
                            format!("STATIC {:x}", address.get())
                        }
                    };
                    Row::new(
                        section.static_address,
                        Some(section.file_offset),
                        section.name,
                        format!(
                            "{native_address} {} vsize {:x} bytes {:x}",
                            section.flags, section.virtual_size, section.file_size
                        ),
                    )
                })
                .collect(),
            Catalog::ElfHeaders | Catalog::ElfSegments | Catalog::ElfSectionHeaders => {
                let (report, layout) =
                    match crate::api::elf_headers::inspect_with_layout(&self.bytes) {
                        Ok(result) => result,
                        Err(error) => {
                            self.status = format!("ELF structure view unavailable: {error:#}");
                            return;
                        }
                    };
                match catalog {
                    Catalog::ElfHeaders => layout
                        .header_fields
                        .into_iter()
                        .map(|field| {
                            Row::new(
                                None,
                                Some(FileOffset(field.range.offset)),
                                field.name,
                                format!(
                                    "{} byte{}  raw {}  {}",
                                    field.range.size,
                                    if field.range.size == 1 { "" } else { "s" },
                                    field.raw,
                                    field.decoded
                                ),
                            )
                        })
                        .collect(),
                    Catalog::ElfSegments => report
                        .segments
                        .into_iter()
                        .zip(layout.programs)
                        .map(|(segment, location)| {
                            let mut row = Row::new(
                                self.base
                                    .checked_add(segment.p_vaddr)
                                    .map(StaticVa),
                                location.content.map(|range| FileOffset(range.offset)),
                                format!("[{}] {}", segment.index, segment.type_name),
                                format!(
                                    "{} flags 0x{:x} file {:x} mem {:x} align {:x} sections {:?}",
                                    segment.permissions,
                                    segment.p_flags,
                                    segment.p_filesz,
                                    segment.p_memsz,
                                    segment.p_align,
                                    segment.section_indices
                                ),
                            );
                            row.record_offset = Some(FileOffset(location.record.offset));
                            row
                        })
                        .collect(),
                    Catalog::ElfSectionHeaders => report
                        .sections
                        .into_iter()
                        .zip(layout.sections)
                        .map(|(section, location)| {
                            let name = section
                                .name
                                .clone()
                                .unwrap_or_else(|| format!("<section {}>", section.index));
                            let address = (section.sh_addr != 0)
                                .then(|| self.base.checked_add(section.sh_addr))
                                .flatten()
                                .map(StaticVa);
                            let mut row = Row::new(
                                address,
                                location.content.map(|range| FileOffset(range.offset)),
                                format!("[{}] {name}", section.index),
                                format!(
                                    "{} type 0x{:x} flags 0x{:x} size {:x} align {:x} link {} info {} entsize {:x}",
                                    section.type_name,
                                    section.sh_type,
                                    section.sh_flags,
                                    section.sh_size,
                                    section.sh_addralign,
                                    section.sh_link,
                                    section.sh_info,
                                    section.sh_entsize
                                ),
                            );
                            row.record_offset = Some(FileOffset(location.record.offset));
                            row
                        })
                        .collect(),
                    _ => unreachable!(),
                }
            }
            Catalog::Bookmarks => match crate::api::bookmarks::list(&self.bin, &self.db) {
                Ok(items) => items
                    .into_iter()
                    .map(|item| {
                        Row::new(
                            Some(item.address),
                            None,
                            item.user_name
                                .unwrap_or_else(|| self.an.label(item.address.get())),
                            format!("USER BOOKMARK {}", item.user_comment.unwrap_or_default()),
                        )
                    })
                    .collect(),
                Err(error) => {
                    self.status = format!("cannot list bookmarks: {error:#}");
                    return;
                }
            },
            Catalog::Imports | Catalog::Exports => {
                let query = symbols::SymbolQuery::default();
                let items = if catalog == Catalog::Imports {
                    symbols::imports_in(&self.an, &query)
                } else {
                    symbols::exports_in(&self.bin, &self.an, &query)
                };
                items
                    .into_iter()
                    .map(|item| {
                        Row::new(
                            item.address,
                            None,
                            item.name,
                            format!("{}  refs {}", item.module, item.reference_count),
                        )
                    })
                    .collect()
            }
            Catalog::Strings => listing::string_summaries(
                &self.bin,
                &self.an,
                &self.strings,
                &listing::StringQuery::default(),
            )
            .into_iter()
            .map(|item| {
                Row::new(
                    Some(StaticVa(item.address)),
                    item.file_offset,
                    item.text,
                    format!(
                        "{} len {} refs {}",
                        if item.wide { "UTF16" } else { "ASCII" },
                        item.len,
                        item.references
                    ),
                )
            })
            .collect(),
        };
        let mut browser = Browser {
            catalog,
            rows,
            visible: Vec::new(),
            selection: 0,
            filter: String::new(),
        };
        browser.filter(String::new());
        self.browser = Some(browser);
        self.left = super::LeftView::Functions;
        self.focus = super::Focus::Functions;
        self.status = if catalog.is_elf_structure() {
            "Enter opens file bytes; O opens the table record; D follows mapped disassembly; / filters"
                .into()
        } else {
            "Enter opens static VA; / filters; :functions returns to functions".into()
        };
    }

    pub fn open_browser_selection(&mut self) {
        let Some(row) = self.browser.as_ref().and_then(Browser::selected) else {
            self.status = "no catalog row selected".into();
            return;
        };
        if let Some(location) = row.navigation.clone() {
            if let Some(current) = self.navigation_location() {
                self.history.push(current);
            }
            self.future.clear();
            self.browser = None;
            self.restore_navigation(location);
            self.status = "restored history location; Backspace returns".into();
            return;
        }
        if self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.catalog.is_elf_structure())
        {
            let Some(offset) = row.file_offset else {
                self.status =
                    "this ELF object has no file-backed bytes (for example SHT_NOBITS)".into();
                return;
            };
            self.open_file_offset(offset.get(), true);
            self.focus = super::Focus::Listing;
            return;
        }
        let Some(address) = row.address else {
            self.status = "no resolved static VA for this catalog row".into();
            return;
        };
        self.open(address.get(), true);
        // Capture the source mode in history before switching the destination.
        if self.graph {
            self.toggle_graph();
        }
        if self.pseudo {
            self.toggle_pseudo();
        }
        self.focus = super::Focus::Listing;
    }

    pub fn open_browser_record(&mut self) {
        let Some(row) = self.browser.as_ref().and_then(Browser::selected) else {
            self.status = "no catalog row selected".into();
            return;
        };
        let offset = row.record_offset.or(row.file_offset);
        let Some(offset) = offset else {
            self.status = "this row has no on-disk structure record".into();
            return;
        };
        self.open_file_offset(offset.get(), true);
        self.focus = super::Focus::Listing;
    }

    pub fn open_browser_disassembly(&mut self) {
        let Some(row) = self.browser.as_ref().and_then(Browser::selected) else {
            self.status = "no catalog row selected".into();
            return;
        };
        let Some(address) = row.address else {
            self.status = "this ELF object has no mapped static address".into();
            return;
        };
        self.open(address.get(), true);
        self.focus = super::Focus::Listing;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_catalog_filter_preserves_selection_and_clamps_empty_results() {
        let rows = (0..50_000)
            .map(|index| {
                Row::new(
                    Some(StaticVa(index)),
                    None,
                    format!("symbol_{index}"),
                    String::new(),
                )
            })
            .collect();
        let mut browser = Browser {
            catalog: Catalog::Imports,
            rows,
            visible: Vec::new(),
            selection: 0,
            filter: String::new(),
        };
        browser.filter(String::new());
        browser.selection = 42_000;
        browser.filter("symbol_42".into());
        assert_eq!(browser.selected().unwrap().address, Some(StaticVa(42_000)));
        browser.filter("absent".into());
        browser.step(isize::MAX);
        assert!(browser.selected().is_none());
        assert_eq!(browser.selection, 0);
    }
}
