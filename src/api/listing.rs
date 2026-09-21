//! Reusable listing indexes and disassembly queries for interactive front ends.

/// Query an existing string index without rebuilding or cloning the workspace.
pub fn string_summaries(
    binary: &Binary,
    analysis: &engine::Analysis,
    strings: &BTreeMap<u64, Located>,
    query: &StringQuery,
) -> Vec<StringSummary> {
    let needle = query
        .text_contains
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    strings
        .iter()
        .filter_map(|(address, string)| {
            if !needle.is_empty() && !string.text.to_lowercase().contains(&needle) {
                return None;
            }
            let references = analysis.xrefs_to.get(address).map_or(0, Vec::len);
            if query.referenced_only && references == 0 {
                return None;
            }
            Some(StringSummary {
                address: *address,
                file_offset: engine::va_to_off(binary, engine::display_base(binary), *address)
                    .and_then(|offset| u64::try_from(offset).ok())
                    .map(FileOffset),
                text: string.text.clone(),
                wide: string.wide,
                len: string.len,
                references,
            })
        })
        .take(query.limit.unwrap_or(usize::MAX))
        .collect()
}

use crate::address::{FileOffset, StaticVa};
use crate::analysis::engine::{self, Function};
use crate::analysis::strings::Located;
use crate::analysis::{disasm, driver, entropy};
use crate::api::driver_surface::{DriverSurface, DriverSurfaceQuery};
use crate::api::risk_signals::RiskSignal;
use crate::listing::{self, Annot, Line};
use crate::model::{Binary, Format, Section};
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PseudocodeLine {
    pub label: bool,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListingAnnotationKind {
    Note,
    Symbol,
    Local,
    Text,
    Hint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingAnnotation {
    pub kind: ListingAnnotationKind,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ListingLine {
    Label {
        address: StaticVa,
        text: String,
    },
    Instruction {
        address: StaticVa,
        mnemonic: String,
        operands: String,
        annotation: Option<ListingAnnotation>,
        target: Option<StaticVa>,
    },
    Data {
        address: StaticVa,
        text: String,
    },
}

impl ListingLine {
    pub const fn address(&self) -> StaticVa {
        match self {
            Self::Label { address, .. }
            | Self::Instruction { address, .. }
            | Self::Data { address, .. } => *address,
        }
    }
}

impl From<Line> for ListingLine {
    fn from(line: Line) -> Self {
        match line {
            Line::Label { addr, text } => Self::Label {
                address: StaticVa(addr),
                text,
            },
            Line::Insn {
                addr,
                mnemonic,
                operands,
                annot,
                target,
            } => Self::Instruction {
                address: StaticVa(addr),
                mnemonic,
                operands,
                annotation: annot.map(ListingAnnotation::from),
                target: target.map(StaticVa),
            },
            Line::Data { addr, text } => Self::Data {
                address: StaticVa(addr),
                text,
            },
        }
    }
}

impl From<Annot> for ListingAnnotation {
    fn from(annotation: Annot) -> Self {
        let (kind, text) = match annotation {
            Annot::Note(text) => (ListingAnnotationKind::Note, text),
            Annot::Symbol(text) => (ListingAnnotationKind::Symbol, text),
            Annot::Local(text) => (ListingAnnotationKind::Local, text),
            Annot::Text(text) => (ListingAnnotationKind::Text, text),
            Annot::Hint(text) => (ListingAnnotationKind::Hint, text),
        };
        Self { kind, text }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringSummary {
    pub address: u64,
    /// File location of the first encoded byte. Kept distinct from the static
    /// address so front ends cannot visually conflate the two address spaces.
    pub file_offset: Option<FileOffset>,
    pub text: String,
    pub wide: bool,
    pub len: u64,
    pub references: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringQuery {
    pub text_contains: Option<String>,
    pub referenced_only: bool,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinearLocation {
    FileOffset(FileOffset),
    StaticVa(StaticVa),
}

impl LinearLocation {
    pub const fn get(self) -> u64 {
        match self {
            Self::FileOffset(value) => value.get(),
            Self::StaticVa(value) => value.get(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LinearRow {
    Region {
        file_offset: FileOffset,
        end_offset: FileOffset,
        name: String,
        segment: String,
        permissions: Option<String>,
        code: bool,
    },
    Label {
        address: StaticVa,
        text: String,
    },
    Function {
        address: StaticVa,
        name: String,
        basic_blocks: usize,
        byte_size: u64,
    },
    Instruction {
        address: StaticVa,
        mnemonic: String,
        operands: String,
        annotation: Option<String>,
        target: Option<StaticVa>,
        segment: String,
    },
    Data {
        location: LinearLocation,
        text: String,
        segment: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearQuery {
    pub file_offset: Option<FileOffset>,
    pub address: Option<StaticVa>,
    pub maximum_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearWindow {
    pub rows: Vec<LinearRow>,
    pub start: FileOffset,
    pub next: Option<FileOffset>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HexQuery {
    pub address: StaticVa,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HexRowSummary {
    pub file_offset: FileOffset,
    pub address: StaticVa,
    pub byte_length: u64,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHexQuery {
    pub file_offset: FileOffset,
    pub length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMapping {
    pub address: StaticVa,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHexRowSummary {
    pub file_offset: FileOffset,
    pub byte_length: u64,
    pub hex: String,
    pub ascii: String,
    /// All image mappings for this byte. Overlapping sections are retained
    /// rather than forcing one arbitrary virtual-address interpretation.
    pub mappings: Vec<FileMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHexWindow {
    pub start: FileOffset,
    pub rows: Vec<FileHexRowSummary>,
    pub previous: Option<FileOffset>,
    pub next: Option<FileOffset>,
}

/// Read an on-disk byte window without requiring the offset to be mapped.
///
/// This is intentionally separate from the virtual-address hex query. Front
/// ends can therefore label and navigate the two address spaces honestly.
pub fn file_hex_window(
    binary: &Binary,
    bytes: &[u8],
    base: u64,
    query: FileHexQuery,
) -> Result<FileHexWindow> {
    let requested = query.length.clamp(16, 65_536);
    let start = usize::try_from(query.file_offset.get())
        .map_err(|_| anyhow!("file offset is too large for this host"))?;
    if start >= bytes.len() {
        return Err(anyhow!("file offset is outside the file"));
    }
    let end = start.saturating_add(requested).min(bytes.len());
    let mut rows = Vec::new();
    for cursor in (start..end).step_by(16) {
        let row_end = cursor.saturating_add(16).min(end);
        let chunk = &bytes[cursor..row_end];
        let offset = u64::try_from(cursor)
            .map(FileOffset)
            .map_err(|_| anyhow!("file offset overflow"))?;
        let mappings = binary
            .sections
            .iter()
            .filter_map(|section| {
                let section_end = section.file_off.checked_add(section.file_size)?;
                let location = offset.get();
                if location < section.file_off || location >= section_end {
                    return None;
                }
                let relative = location.checked_sub(section.file_off)?;
                let address = base.checked_add(section.vaddr)?.checked_add(relative)?;
                Some(FileMapping {
                    address: StaticVa(address),
                    region: section.name.clone(),
                })
            })
            .collect();
        rows.push(FileHexRowSummary {
            file_offset: offset,
            byte_length: chunk.len() as u64,
            hex: chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
            ascii: chunk
                .iter()
                .map(|byte| {
                    if (0x20..=0x7e).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect(),
            mappings,
        });
    }
    let next = (end < bytes.len()).then_some(FileOffset(end as u64));
    let previous = (start != 0).then(|| FileOffset(start.saturating_sub(requested) as u64));
    Ok(FileHexWindow {
        start: query.file_offset,
        rows,
        previous,
        next,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverviewBucketSummary {
    pub file_offset: FileOffset,
    pub static_address: Option<StaticVa>,
    pub entropy: f64,
    pub section: Option<String>,
    pub code: bool,
    pub risk_signals: u32,
    pub maximum_severity: u8,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverviewSummary {
    pub size: u64,
    pub bucket_bytes: u64,
    pub buckets: Vec<OverviewBucketSummary>,
    pub entry_bucket: Option<usize>,
}

/// Name-independent strings and name-dependent driver annotations used to
/// render listings. Build once per session and refresh after recovery changes.
pub struct ListingIndex {
    base: u64,
    strings: BTreeMap<u64, Located>,
    hints: Option<BTreeMap<u64, String>>,
}

impl ListingIndex {
    pub fn from_session(session: &Session) -> Self {
        let base = engine::display_base(&session.bin);
        let strings = listing::string_map(&session.bin, &session.bytes, base);
        let hints = driver::plausibly_a_driver(&session.bin)
            .then(|| driver::listing_hints(&session.bin, &session.bytes, &session.an));
        Self {
            base,
            strings,
            hints,
        }
    }

    /// Refresh facts that can change after analyst names alter recovery.
    pub fn refresh_analysis(&mut self, session: &Session) {
        self.base = engine::display_base(&session.bin);
        self.hints = driver::plausibly_a_driver(&session.bin)
            .then(|| driver::listing_hints(&session.bin, &session.bytes, &session.an));
    }

    pub const fn base(&self) -> u64 {
        self.base
    }

    pub fn strings(&self, session: &Session, query: &StringQuery) -> Vec<StringSummary> {
        string_summaries(&session.bin, &session.an, &self.strings, query)
    }

    pub const fn has_driver_hints(&self) -> bool {
        self.hints.is_some()
    }

    pub fn function_lines(&self, session: &Session, function: &Function) -> Vec<ListingLine> {
        listing::function(
            &session.an,
            function,
            &session.db,
            self.base,
            &self.strings,
            self.hints.as_ref(),
        )
        .into_iter()
        .map(ListingLine::from)
        .collect()
    }

    pub fn function_lines_by_selector(
        &self,
        session: &Session,
        selector: &str,
    ) -> Result<Vec<ListingLine>> {
        let function = resolve_function(session, selector)
            .ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
        Ok(self.function_lines(session, function))
    }

    pub fn pseudocode(&self, session: &Session, function: &Function) -> Vec<PseudocodeLine> {
        crate::analysis::ir::decompile(
            &session.an,
            &session.bin,
            function,
            &self.strings,
            &session.db,
        )
        .into_iter()
        .map(|line| PseudocodeLine {
            label: line.label,
            text: line.text,
        })
        .collect()
    }

    pub fn pseudocode_by_selector(
        &self,
        session: &Session,
        selector: &str,
    ) -> Result<Vec<PseudocodeLine>> {
        let function = resolve_function(session, selector)
            .ok_or_else(|| anyhow!("nothing matches {selector:?}"))?;
        Ok(self.pseudocode(session, function))
    }

    pub fn driver_surface(&self, session: &Session) -> Option<DriverSurface> {
        driver::plausibly_a_driver(&session.bin)
            .then(|| driver::report(&session.bin, &session.bytes, &session.an, &self.strings))
            .filter(|report| report.is_driver)
            .map(|report| DriverSurface::from_report(&report, DriverSurfaceQuery::default()))
    }

    /// Render a function selected by name/address, or mapped data selected by
    /// address. This preserves the GUI/TUI behavior that every mapped address
    /// is navigable even when it is not recovered code.
    pub fn disassemble(&self, session: &Session, selector: &str) -> Result<Vec<ListingLine>> {
        if let Some(function) = resolve_function(session, selector) {
            return Ok(self.function_lines(session, function));
        }
        let address =
            parse_address(selector).map_err(|_| anyhow!("nothing matches {selector:?}"))?;
        if engine::va_to_off(&session.bin, self.base, address).is_none() {
            return Err(anyhow!("{selector} is not mapped in this image"));
        }
        Ok(
            listing::data_view(&session.bin, self.base, &session.bytes, address)
                .into_iter()
                .map(ListingLine::from)
                .collect(),
        )
    }

    pub fn hex_window(&self, session: &Session, query: HexQuery) -> Result<Vec<HexRowSummary>> {
        let offset = engine::va_to_off(&session.bin, self.base, query.address.get())
            .ok_or_else(|| anyhow!("address is not in any mapped section"))?;
        let length = query.length.clamp(16, 1024);
        let start = offset.min(session.bytes.len());
        let end = start.saturating_add(length).min(session.bytes.len());
        let mut rows = Vec::new();
        let mut cursor = start;
        while cursor < end {
            let relative = u64::try_from(cursor - start)
                .map_err(|_| anyhow!("hex window row offset overflow"))?;
            let expected_address = query
                .address
                .get()
                .checked_add(relative)
                .ok_or_else(|| anyhow!("hex window address overflow"))?;
            let file_offset = u64::try_from(cursor)
                .map(FileOffset)
                .map_err(|_| anyhow!("hex window file offset overflow"))?;
            if engine::off_to_va(&session.bin, self.base, file_offset.get())
                != Some(expected_address)
            {
                break;
            }

            let maximum_row_end = cursor.saturating_add(16).min(end);
            let mut row_end = cursor + 1;
            while row_end < maximum_row_end {
                let byte_relative = u64::try_from(row_end - start)
                    .map_err(|_| anyhow!("hex window byte offset overflow"))?;
                let Some(byte_address) = query.address.get().checked_add(byte_relative) else {
                    break;
                };
                let byte_offset = u64::try_from(row_end)
                    .map_err(|_| anyhow!("hex window file offset overflow"))?;
                if engine::off_to_va(&session.bin, self.base, byte_offset) != Some(byte_address) {
                    break;
                }
                row_end += 1;
            }

            let chunk = &session.bytes[cursor..row_end];
            let address = StaticVa(expected_address);
            let byte_length = u64::try_from(chunk.len())
                .map_err(|_| anyhow!("hex window row length overflow"))?;
            let hex = chunk
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii = chunk
                .iter()
                .map(|byte| {
                    if (0x20..=0x7e).contains(byte) {
                        *byte as char
                    } else {
                        '.'
                    }
                })
                .collect();
            rows.push(HexRowSummary {
                file_offset,
                address,
                byte_length,
                hex,
                ascii,
            });
            cursor = row_end;
        }
        if rows.is_empty() {
            return Err(anyhow!(
                "address mapping is ambiguous between virtual and file locations"
            ));
        }
        Ok(rows)
    }

    pub fn linear(&self, session: &Session, query: &LinearQuery) -> Result<LinearWindow> {
        let maximum_rows = query.maximum_rows.clamp(1, 20_000);
        let file_size = u64::try_from(session.bytes.len()).unwrap_or(u64::MAX);
        let mut cursor = match (query.file_offset, query.address) {
            (Some(offset), _) => offset.get(),
            (None, Some(address)) => engine::va_to_off(&session.bin, self.base, address.get())
                .map(|offset| offset as u64)
                .ok_or_else(|| anyhow!("address is not in any mapped section"))?,
            (None, None) => 0,
        };
        let start = FileOffset(cursor);
        if cursor >= file_size {
            return Ok(LinearWindow {
                rows: Vec::new(),
                start,
                next: None,
            });
        }

        let regions = file_regions(&session.bin, file_size);
        let entry_offset = disasm::entry_location(&session.bin, &session.bytes).map(|(off, _)| off);
        let mut rows = Vec::new();
        while rows.len() < maximum_rows && cursor < file_size {
            let Some(region) = regions
                .iter()
                .find(|region| cursor >= region.start && cursor < region.end)
            else {
                break;
            };
            let before = cursor;
            if cursor == region.start || rows.is_empty() {
                rows.push(LinearRow::Region {
                    file_offset: FileOffset(cursor),
                    end_offset: FileOffset(region.end),
                    name: region.name.clone(),
                    segment: region.segment.clone(),
                    permissions: region.permissions.clone(),
                    code: region.code,
                });
            }

            if region.code && disasm::supported(session.bin.arch) {
                let address = engine::off_to_va(&session.bin, self.base, cursor).unwrap_or(cursor);
                let room = maximum_rows.saturating_sub(rows.len()).max(1);
                let instructions = disasm::disassemble(
                    &session.bytes,
                    cursor,
                    address,
                    session.bin.bits,
                    session.bin.arch,
                    room,
                );
                if instructions.is_empty() {
                    cursor = region.end;
                    continue;
                }
                for instruction in &instructions {
                    let instruction_len = instruction.bytes.len() as u64;
                    if cursor + instruction_len > region.end {
                        break;
                    }
                    if Some(cursor) == entry_offset {
                        rows.push(LinearRow::Label {
                            address: StaticVa(instruction.addr),
                            text: "entry point:".into(),
                        });
                    }
                    if let Some(function) = session.an.find_function(instruction.addr) {
                        if function.addr == instruction.addr && Some(cursor) != entry_offset {
                            rows.push(LinearRow::Function {
                                address: StaticVa(instruction.addr),
                                name: function.name.clone(),
                                basic_blocks: function.blocks.len(),
                                byte_size: function.size,
                            });
                        }
                    }
                    let (mnemonic, operands) =
                        match instruction.text.split_once(char::is_whitespace) {
                            Some((mnemonic, rest)) => {
                                (mnemonic.to_string(), rest.trim_start().to_string())
                            }
                            None => (instruction.text.clone(), String::new()),
                        };
                    let target = trailing_address(&operands).filter(|target| {
                        session.an.find_function(*target).is_some()
                            || session.an.imports.contains_key(target)
                    });
                    rows.push(LinearRow::Instruction {
                        address: StaticVa(instruction.addr),
                        mnemonic,
                        operands,
                        annotation: target.map(|target| session.an.label(target)),
                        target: target.map(StaticVa),
                        segment: region.segment.clone(),
                    });
                    cursor += instruction_len;
                }
            } else {
                while rows.len() < maximum_rows && cursor < region.end {
                    let end = (cursor + 16).min(region.end).min(file_size);
                    let chunk = &session.bytes[cursor as usize..end as usize];
                    let hex_bytes = chunk
                        .iter()
                        .map(|byte| format!("{byte:02x} "))
                        .collect::<String>();
                    let ascii = chunk
                        .iter()
                        .map(|byte| {
                            if (0x20..=0x7e).contains(byte) {
                                *byte as char
                            } else {
                                '.'
                            }
                        })
                        .collect::<String>();
                    let location = engine::off_to_va(&session.bin, self.base, cursor)
                        .map(|address| LinearLocation::StaticVa(StaticVa(address)))
                        .unwrap_or(LinearLocation::FileOffset(FileOffset(cursor)));
                    rows.push(LinearRow::Data {
                        location,
                        text: format!("{hex_bytes:<48} {ascii}"),
                        segment: region.segment.clone(),
                    });
                    cursor = end;
                }
            }

            if cursor == before {
                if rows.len() >= maximum_rows {
                    break;
                }
                cursor = region.end;
            }
        }
        Ok(LinearWindow {
            rows,
            start,
            next: (cursor < file_size).then_some(FileOffset(cursor)),
        })
    }

    pub fn overview(
        &self,
        session: &Session,
        requested_buckets: usize,
        signals: &[RiskSignal],
    ) -> OverviewSummary {
        let bytes = &session.bytes;
        if bytes.is_empty() {
            return OverviewSummary {
                size: 0,
                bucket_bytes: 0,
                buckets: Vec::new(),
                entry_bucket: None,
            };
        }
        let count = requested_buckets.clamp(64, 2048);
        let step = bytes.len().div_ceil(count).max(1);
        let mut buckets: Vec<_> = bytes
            .chunks(step)
            .enumerate()
            .map(|(index, chunk)| {
                let offset = (index * step) as u64;
                let section = session.bin.sections.iter().find(|section| {
                    section.file_size > 0
                        && offset >= section.file_off
                        && offset < section.file_off + section.file_size
                });
                OverviewBucketSummary {
                    file_offset: FileOffset(offset),
                    static_address: engine::off_to_va(&session.bin, self.base, offset)
                        .map(StaticVa),
                    entropy: entropy::entropy(chunk),
                    section: section.map(|section| section.name.clone()),
                    code: section.is_some_and(|section| section.exec),
                    risk_signals: 0,
                    maximum_severity: 0,
                }
            })
            .collect();
        let last = buckets.len().saturating_sub(1);
        for signal in signals {
            if let Some(offset) = engine::va_to_off(&session.bin, self.base, signal.address.get()) {
                let bucket = &mut buckets[(offset / step).min(last)];
                bucket.risk_signals += 1;
                bucket.maximum_severity = bucket.maximum_severity.max(signal.severity);
            }
        }
        let entry_bucket = disasm::entry_location(&session.bin, &session.bytes)
            .map(|(offset, _)| (offset as usize / step).min(last));
        OverviewSummary {
            size: bytes.len() as u64,
            bucket_bytes: step as u64,
            buckets,
            entry_bucket,
        }
    }
}

struct FileRegion {
    start: u64,
    end: u64,
    name: String,
    segment: String,
    permissions: Option<String>,
    code: bool,
}

fn section_permissions(section: &Section) -> String {
    let bit = |enabled: bool, marker: char| if enabled { marker } else { '-' };
    format!(
        "{}{}{}",
        bit(section.read, 'R'),
        bit(section.write, 'W'),
        bit(section.exec, 'X')
    )
}

fn file_regions(binary: &Binary, file_size: u64) -> Vec<FileRegion> {
    let mut sections: Vec<_> = binary
        .sections
        .iter()
        .filter(|section| section.file_size > 0)
        .collect();
    sections.sort_by_key(|section| section.file_off);
    let mut regions = Vec::new();
    let mut cursor = 0u64;
    for section in sections {
        if section.file_off > cursor {
            let headers = cursor == 0;
            regions.push(FileRegion {
                start: cursor,
                end: section.file_off.min(file_size),
                name: if headers && binary.format == Format::Pe {
                    "DOS header, stub, and PE headers".into()
                } else if headers {
                    "container headers".into()
                } else {
                    "alignment padding".into()
                },
                segment: if headers { "HEADER" } else { "align" }.into(),
                permissions: None,
                code: false,
            });
        }
        let end = section
            .file_off
            .saturating_add(section.file_size)
            .min(file_size);
        let start = section.file_off.max(cursor);
        if end > start {
            regions.push(FileRegion {
                start,
                end,
                name: section.name.clone(),
                segment: section.name.clone(),
                permissions: Some(section_permissions(section)),
                code: section.exec,
            });
        }
        cursor = cursor.max(end);
    }
    if file_size > cursor {
        regions.push(FileRegion {
            start: cursor,
            end: file_size,
            name: "overlay".into(),
            segment: "overlay".into(),
            permissions: None,
            code: false,
        });
    }
    if regions.is_empty() {
        regions.push(FileRegion {
            start: 0,
            end: file_size,
            name: "file".into(),
            segment: "file".into(),
            permissions: None,
            code: false,
        });
    }
    regions
}

fn trailing_address(operands: &str) -> Option<u64> {
    let at = operands.rfind("0x")?;
    let digits: String = operands[at + 2..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    if operands[at..].contains(']') {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

fn resolve_function<'a>(session: &'a Session, selector: &str) -> Option<&'a Function> {
    if let Some(function) = session.an.find_by_name(selector) {
        return Some(function);
    }
    parse_address(selector).ok().and_then(|address| {
        session
            .an
            .find_function(address)
            .or_else(|| session.an.function_at(address))
    })
}

fn parse_address(value: &str) -> Result<u64> {
    let raw = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(raw, 16).map_err(Into::into)
}
