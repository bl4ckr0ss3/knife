//! WebAssembly module parsing. Self-contained: goblin dropped its wasm module,
//! so the section walk is implemented here against the core spec — LEB128
//! readers with strict bounds, one pass over the section table, and per-section
//! parsers that degrade a single section to "opaque" instead of failing the
//! whole file. Like every format module here, the job is to flatten the
//! container into the neutral [`Binary`] model.
//!
//! Scope is triage: sections, imports grouped by module, exports, custom
//! sections (`producers` toolchain, `name` symbol presence), and the start
//! function. There is no wasm lifter downstream — the disassembler refuses
//! [`Arch::Wasm`] — so function bodies are counted and located, not decoded.

use super::mk_section;
use crate::model::{Arch, Binary, Format, ImportedLib, SymKind, Symbol};
use anyhow::{bail, Result};

/// Section ids from the wasm core spec. Custom (0) carries its own name.
const SEC_CUSTOM: u8 = 0;
const SEC_TYPE: u8 = 1;
const SEC_IMPORT: u8 = 2;
const SEC_FUNCTION: u8 = 3;
const SEC_TABLE: u8 = 4;
const SEC_MEMORY: u8 = 5;
const SEC_GLOBAL: u8 = 6;
const SEC_EXPORT: u8 = 7;
const SEC_START: u8 = 8;
const SEC_ELEM: u8 = 9;
const SEC_CODE: u8 = 10;
const SEC_DATA: u8 = 11;
const SEC_DATACOUNT: u8 = 12;

fn section_label(id: u8) -> &'static str {
    match id {
        SEC_TYPE => "type",
        SEC_IMPORT => "import",
        SEC_FUNCTION => "function",
        SEC_TABLE => "table",
        SEC_MEMORY => "memory",
        SEC_GLOBAL => "global",
        SEC_EXPORT => "export",
        SEC_START => "start",
        SEC_ELEM => "elem",
        SEC_CODE => "code",
        SEC_DATA => "data",
        SEC_DATACOUNT => "datacount",
        SEC_TRAILING => "trailing",
        _ => "unknown",
    }
}

/// A flat section record: one row in the section table.
struct RawSection {
    id: u8,
    /// Only for custom sections.
    name: Option<String>,
    /// On-disk start of the whole section (id byte included).
    off: u64,
    /// On-disk size: id + size prefix + payload.
    size: u64,
    /// Payload range, where content parsers start.
    payload_off: u64,
    payload_len: u64,
    /// The section header claimed more bytes than the file holds.
    truncated: bool,
}

/// Synthesized section id for bytes past a broken section table.
const SEC_TRAILING: u8 = 0xFF;

struct WasmInfo {
    /// `(module, function-name)` import pairs, in file order.
    import_funcs: Vec<(String, String)>,
    /// Non-function imports (tables/memories/globals/tags), by kind label.
    other_imports: Vec<&'static str>,
    /// Number of function type signatures declared.
    type_count: usize,
    /// Function *declarations* (index space; excludes imported functions).
    func_decls: usize,
    /// Function bodies found in the code section, as `(file offset, size)`.
    func_bodies: Vec<(u64, u64)>,
    exports: Vec<String>,
    /// `(kind label, index, name)` — exports may name memories/tables/globals too.
    export_kinds: Vec<(&'static str, u32, String)>,
    start_func: Option<u32>,
    /// Memory declarations as `(min pages, max pages)`.
    memories: Vec<(u32, Option<u32>)>,
    globals: usize,
    tables: usize,
    elem_segments: usize,
    data_segments: usize,
    /// Active data segments as `(load address, file offset, length)` — the
    /// pointer map that turns image u32s into file positions.
    data_ranges: Vec<(u64, u64, u64)>,
    /// `name` custom section: function index → name map.
    func_names: Vec<(u32, String)>,
    /// `name` custom section: module name, when present.
    module_name: Option<String>,
    /// Custom section names, in file order.
    customs: Vec<String>,
    /// Decoded `producers` section, as `field: name version, …` lines.
    producers: Option<String>,
    /// Present when the `name` custom section exists (symbol names survive).
    has_name_section: bool,
}

// ── low-level readers ──────────────────────────────────────────────────────

/// Cursor with bounds-checked reads; every accessor returns `Option` so a
/// truncated file degrades instead of panicking. This is hostile-input code.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8]) -> Cur<'a> {
        Cur { b, p: 0 }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }
    /// Unsigned LEB128, rejecting non-canonical overlong encodings past 5
    /// bytes and shift overflow the same way the spec's u32 type does.
    fn uleb(&mut self) -> Option<u32> {
        let mut out: u32 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            let low = (byte & 0x7f) as u32;
            if shift >= 32 || (shift == 28 && low > 0x0f) {
                return None;
            }
            out |= low << shift;
            if byte & 0x80 == 0 {
                return Some(out);
            }
            shift += 7;
        }
    }
    /// Name: u32 length + bytes, decoded as lossy UTF-8 so a bad module still
    /// yields a printable label rather than a parse failure.
    fn name(&mut self) -> Option<String> {
        let n = self.uleb()? as usize;
        let raw = self.bytes(n)?;
        Some(String::from_utf8_lossy(raw).into_owned())
    }
    /// Limits: flags byte, then min (and max when flags bit 0 set). Later
    /// proposals add more flags; anything unexpected degrades to min only.
    fn limits(&mut self) -> Option<(u32, Option<u32>)> {
        let flags = self.u8()?;
        let min = self.uleb()?;
        let max = if flags & 0x01 != 0 {
            Some(self.uleb()?)
        } else {
            None
        };
        Some((min, max))
    }
    /// Skip one constant-expression (init expr, elem/data offsets). Walks the
    /// handful of core opcodes with immediates; `0x0b` ends; anything else
    /// aborts the walk and the caller degrades the enclosing section.
    fn skip_expr(&mut self) -> Option<()> {
        loop {
            match self.u8()? {
                0x0b => return Some(()),
                0x41 => {
                    self.sleb_i64()?;
                }
                0x42 => {
                    self.sleb_i64()?;
                }
                0x43 => {
                    self.bytes(4)?;
                }
                0x44 => {
                    self.bytes(8)?;
                }
                0x23 | 0x24 | 0xD2 => {
                    self.uleb()?;
                }
                _ => return None,
            }
        }
    }
    /// Signed LEB128 widened to i64; only used to skip immediates.
    fn sleb_i64(&mut self) -> Option<i64> {
        let mut out: i64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            let low = (byte & 0x7f) as i64;
            if shift >= 64 {
                return None;
            }
            out |= low << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    out |= -1i64 << shift;
                }
                return Some(out);
            }
        }
    }
    /// Skip a vector of `valtype` bytes (type-section parameter/result lists).
    fn skip_valtypes(&mut self) -> Option<usize> {
        let n = self.uleb()? as usize;
        for _ in 0..n {
            let t = self.u8()?;
            // 0x7f..0x70 are the core valtypes; heap types (0x63/0x64/…) and
            // typed references carry extra immediates the triage parser does
            // not model. Refuse rather than mis-walk.
            if !matches!(t, 0x7f | 0x7e | 0x7d | 0x7c | 0x7b | 0x70 | 0x6f) {
                return None;
            }
        }
        Some(n)
    }
}

// ── section walk ───────────────────────────────────────────────────────────

/// Walk the section table. Every section's claimed range is clamped to the
/// file so a lying header cannot point the content parsers out of bounds —
/// the same clamping discipline `mk_section` applies everywhere else.
///
/// A malformed section header does not fail the file: the sections that did
/// parse stay in the table and whatever remains is recorded as one `trailing`
/// region, the same way a carver would treat it.
fn walk_sections(bytes: &[u8]) -> Result<(u32, Vec<RawSection>)> {
    if bytes.len() < 8 || bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
        bail!("not a WebAssembly module (bad magic)");
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let mut sections = Vec::new();
    let mut pos = 8usize;
    while pos < bytes.len() {
        let id = bytes[pos];
        // Size prefix parsed one byte past the id, so a bad prefix leaves the
        // whole section (id included) for the trailing region.
        let mut c = Cur::new(&bytes[pos + 1..]);
        let Some(size) = c.uleb() else { break };
        let hdr_len = 1 + c.p;
        let payload_start = pos + hdr_len;
        let payload_end = payload_start.saturating_add(size as usize).min(bytes.len());
        let truncated = payload_end < payload_start + size as usize;
        sections.push(RawSection {
            id,
            name: None,
            off: pos as u64,
            size: (payload_end - pos) as u64,
            payload_off: payload_start as u64,
            payload_len: (payload_end - payload_start) as u64,
            truncated,
        });
        if id == SEC_CUSTOM {
            let mut pc = Cur::new(&bytes[payload_start..payload_end]);
            if let Some(nm) = pc.name() {
                if let Some(last) = sections.last_mut() {
                    last.name = Some(nm);
                }
            }
        }
        // Always advances: a zero-size section still consumed its header.
        pos = payload_end;
    }
    if pos < bytes.len() {
        sections.push(RawSection {
            id: SEC_TRAILING,
            name: None,
            off: pos as u64,
            size: (bytes.len() - pos) as u64,
            payload_off: pos as u64,
            payload_len: (bytes.len() - pos) as u64,
            truncated: false,
        });
    }
    Ok((version, sections))
}

// ── per-section parsers ────────────────────────────────────────────────────

fn parse_type(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        let form = c.u8()?;
        // 0x60 = func. Typed function references (0x62/0x63 forms) carry
        // immediates this parser does not model; degrade the section.
        if form != 0x60 {
            return None;
        }
        c.skip_valtypes()?;
        c.skip_valtypes()?;
    }
    info.type_count = n as usize;
    Some(())
}

fn parse_import(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        let module = c.name()?;
        let field = c.name()?;
        match c.u8()? {
            0 => {
                c.uleb()?;
                info.import_funcs.push((module, field));
            }
            1 => {
                c.u8()?;
                c.limits()?;
                info.other_imports.push("table");
            }
            2 => {
                c.limits()?;
                info.other_imports.push("memory");
            }
            3 => {
                c.u8()?;
                c.u8()?;
                info.other_imports.push("global");
            }
            4 => {
                // tag/exception: attribute byte + tag type vector
                c.u8()?;
                let m = c.uleb()?;
                for _ in 0..m {
                    c.u8()?;
                }
                info.other_imports.push("tag");
            }
            _ => return None,
        }
    }
    Some(())
}

fn parse_function(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        c.uleb()?;
    }
    info.func_decls = n as usize;
    Some(())
}

fn parse_table(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        c.u8()?;
        c.limits()?;
        info.tables += 1;
    }
    Some(())
}

fn parse_memory(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        info.memories.push(c.limits()?);
    }
    Some(())
}

fn parse_global(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        c.u8()?; // valtype
        c.u8()?; // mutability
        c.skip_expr()?;
    }
    info.globals = n as usize;
    Some(())
}

fn export_kind(k: u8) -> Option<&'static str> {
    match k {
        0 => Some("func"),
        1 => Some("table"),
        2 => Some("mem"),
        3 => Some("global"),
        4 => Some("tag"),
        _ => None,
    }
}

fn parse_export(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        let name = c.name()?;
        let kind = export_kind(c.u8()?)?;
        let idx = c.uleb()?;
        info.exports.push(name.clone());
        info.export_kinds.push((kind, idx, name));
    }
    Some(())
}

fn parse_start(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    info.start_func = Some(c.uleb()?);
    Some(())
}

fn parse_elem(info: &mut WasmInfo, payload: &[u8]) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    info.elem_segments = n as usize;
    for _ in 0..n {
        // Merged-spec encoding: bit 0 = passive/declarative, bit 1 = explicit
        // table index, bit 2 = elements are expressions rather than indices.
        let flags = c.uleb()?;
        if flags & 0b001 == 0 {
            // active: optional table index, then the offset expression, then
            // the element vector with no type byte.
            if flags & 0b010 != 0 {
                c.uleb()?;
            }
            c.skip_expr()?;
        } else {
            // passive/declarative: elemkind (indices) or reftype (exprs).
            c.u8()?;
        }
        let m = c.uleb()?;
        for _ in 0..m {
            if flags & 0b100 != 0 {
                c.skip_expr()?;
            } else {
                c.uleb()?;
            }
        }
    }
    Some(())
}

fn parse_code(info: &mut WasmInfo, payload: &[u8], payload_off: u64) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        let body_size = c.uleb()? as usize;
        let body_off = payload_off + c.p as u64;
        if c.bytes(body_size).is_none() {
            return None;
        }
        info.func_bodies.push((body_off, body_size as u64));
    }
    Some(())
}

fn parse_data(info: &mut WasmInfo, payload: &[u8], payload_off: u64) -> Option<()> {
    let mut c = Cur::new(payload);
    let n = c.uleb()?;
    for _ in 0..n {
        let flags = c.uleb()?;
        match flags {
            0 => {
                // active, implicit memory 0: offset expr, then the bytes. The
                // offset is the segment's load address — what image pointers
                // name — and the byte vector's file position is where those
                // bytes live, so the pair becomes a pointer-map range.
                let mem = read_const_expr(&payload[c.p..])?;
                c.skip_expr()?;
                let m = c.uleb()? as usize;
                let file = payload_off + c.p as u64;
                c.bytes(m)?;
                info.data_ranges.push((mem as u64, file, m as u64));
            }
            1 => {
                let m = c.uleb()? as usize;
                c.bytes(m)?;
            }
            2 => {
                c.uleb()?;
                let mem = read_const_expr(&payload[c.p..])?;
                c.skip_expr()?;
                let m = c.uleb()? as usize;
                let file = payload_off + c.p as u64;
                c.bytes(m)?;
                info.data_ranges.push((mem as u64, file, m as u64));
            }
            _ => return None,
        }
        info.data_segments += 1;
    }
    Some(())
}

/// Value of a `i32.const N; end` / `i64.const N; end` offset expression — the
/// shape every data-segment offset uses. Anything else is not supported for
/// pointer mapping (the segment still parses; it just does not map).
fn read_const_expr(payload: &[u8]) -> Option<i64> {
    let mut c = Cur::new(payload);
    match c.u8()? {
        0x41 | 0x42 => c.sleb_i64(),
        _ => None,
    }
}

/// The `name` custom section: a vector of subsections, each an id byte, a
/// size prefix, and a payload. Subsection 1 is the function-name map — the
/// one that matters for triage: real symbols without a lifter. Malformed
/// subsections are skipped, not fatal.
fn decode_name_section(info: &mut WasmInfo, payload: &[u8]) {
    let mut c = Cur::new(payload);
    loop {
        let Some(sub) = c.u8() else { break };
        let Some(sz) = c.uleb() else { break };
        let end = (c.p + sz as usize).min(payload.len());
        let sub_payload = &payload[c.p..end];
        match sub {
            0 => {
                let mut mc = Cur::new(sub_payload);
                if let Some(m) = mc.name() {
                    info.module_name = Some(m);
                }
            }
            1 => {
                let mut mc = Cur::new(sub_payload);
                if let Some(n) = mc.uleb() {
                    for _ in 0..n {
                        match (mc.uleb(), mc.name()) {
                            (Some(i), Some(name)) => info.func_names.push((i, name)),
                            _ => break,
                        }
                    }
                }
            }
            _ => {} // local names (2), globals/… (4+) — not triage material
        }
        c.p = end;
    }
}

/// `producers`: a vector of (field name, vector of (tool name, version)).
fn parse_producers(payload: &[u8]) -> Option<String> {
    let mut c = Cur::new(payload);
    let fields = c.uleb()?;
    let mut out = Vec::new();
    for _ in 0..fields {
        let field = c.name()?;
        let n = c.uleb()?;
        let mut tools = Vec::new();
        for _ in 0..n {
            let name = c.name()?;
            let version = c.name()?;
            tools.push(format!("{name} {version}"));
        }
        out.push(format!("{}: {}", field, tools.join(", ")));
    }
    Some(out.join("; "))
}

/// Returns whether the section contents were fully walked. A `false` keeps
/// the section row and adds a note, but never fails the file.
fn parse_content(info: &mut WasmInfo, sec: &RawSection, bytes: &[u8]) -> bool {
    let payload = &bytes[sec.payload_off as usize..(sec.payload_off + sec.payload_len) as usize];
    if sec.id == SEC_CUSTOM || sec.id == SEC_TRAILING {
        if sec.id == SEC_CUSTOM {
            if let Some(nm) = &sec.name {
                info.customs.push(nm.clone());
                if nm == "name" {
                    info.has_name_section = true;
                    // Payload after the section name: named subsections.
                    let mut nc = Cur::new(payload);
                    let _ = nc.name();
                    decode_name_section(info, &payload[nc.p.min(payload.len())..]);
                }
                if nm == "producers" {
                    // Payload after the section name.
                    let mut c = Cur::new(payload);
                    let _ = c.name(); // skip the section name
                    if let Some(p) = parse_producers(&payload[c.p.min(payload.len())..]) {
                        info.producers = Some(p);
                    }
                }
            }
        }
        return true;
    }
    let walked = match sec.id {
        SEC_TYPE => parse_type(info, payload),
        SEC_IMPORT => parse_import(info, payload),
        SEC_FUNCTION => parse_function(info, payload),
        SEC_TABLE => parse_table(info, payload),
        SEC_MEMORY => parse_memory(info, payload),
        SEC_GLOBAL => parse_global(info, payload),
        SEC_EXPORT => parse_export(info, payload),
        SEC_START => parse_start(info, payload),
        SEC_ELEM => parse_elem(info, payload),
        SEC_CODE => parse_code(info, payload, sec.payload_off),
        SEC_DATA => parse_data(info, payload, sec.payload_off),
        SEC_DATACOUNT => Some(()), // the count is redundant with the data walk
        _ => Some(()),
    };
    walked.is_some()
}

// ── Binary construction ────────────────────────────────────────────────────

/// Parse a wasm module into the neutral model. Only the section *table* is
/// load-bearing: a section whose contents will not walk still appears with
/// correct bytes and entropy, and the failure is recorded in `notes`.
pub fn build(path: &str, bytes: &[u8]) -> Result<Binary> {
    let (version, sections) = walk_sections(bytes)?;

    let mut info = WasmInfo {
        import_funcs: Vec::new(),
        other_imports: Vec::new(),
        type_count: 0,
        func_decls: 0,
        func_bodies: Vec::new(),
        exports: Vec::new(),
        export_kinds: Vec::new(),
        start_func: None,
        memories: Vec::new(),
        globals: 0,
        tables: 0,
        elem_segments: 0,
        data_segments: 0,
        data_ranges: Vec::new(),
        func_names: Vec::new(),
        module_name: None,
        customs: Vec::new(),
        producers: None,
        has_name_section: false,
    };

    let mut notes = Vec::new();
    let mut degraded: Vec<&str> = Vec::new();
    for sec in &sections {
        if sec.truncated {
            notes.push(format!(
                "section '{}' claims more bytes than the file holds; clamped",
                sec.name.clone().unwrap_or_else(|| section_label(sec.id).to_string())
            ));
        }
        // A section that failed to walk keeps its row but flags the miss.
        if !parse_content(&mut info, sec, bytes)
            && sec.id != SEC_CUSTOM
            && sec.id != SEC_TRAILING
            && sec.id != SEC_DATACOUNT
        {
            degraded.push(section_label(sec.id));
        }
    }
    if !degraded.is_empty() {
        notes.push(format!(
            "section(s) present but not fully walked: {}",
            degraded.join(", ")
        ));
    }

    // The section table drives every byte view. Addresses are the file
    // offsets themselves: wasm has no image base, and the identity map lets
    // `read_bytes`/`hex`/diff offsets line up with the section table.
    let mut model_sections = Vec::new();
    for sec in &sections {
        let name = sec
            .name
            .clone()
            .unwrap_or_else(|| section_label(sec.id).to_string());
        let (read, write, exec) = match sec.id {
            SEC_CODE => (true, false, true),
            SEC_DATA | SEC_GLOBAL | SEC_MEMORY => (true, true, false),
            _ => (true, false, false),
        };
        model_sections.push(mk_section(
            name, sec.off, sec.size, sec.off, sec.size, read, write, exec, bytes,
        ));
    }

    // Wasm imports are grouped by module exactly like PE libraries, so the
    // existing `imports`/capabilities views work unmodified.
    let mut imports: Vec<ImportedLib> = Vec::new();
    for (module, func) in &info.import_funcs {
        match imports.iter_mut().find(|l| &l.name == module) {
            Some(lib) => lib.functions.push(func.clone()),
            None => imports.push(ImportedLib {
                name: module.clone(),
                functions: vec![func.clone()],
                ordinals: Vec::new(),
            }),
        }
    }

    let mut libs: Vec<String> = imports.iter().map(|l| l.name.clone()).collect();
    libs.sort();
    libs.dedup();

    if let Some(p) = &info.producers {
        notes.push(format!("producers: {p}"));
    }
    if version != 1 {
        notes.push(format!("module version {version} (spec version is 1)"));
    }
    if info.has_name_section {
        notes.push(format!(
            "custom 'name' section: {} function name(s){}",
            info.func_names.len(),
            info.module_name
                .as_ref()
                .map(|m| format!(", module '{m}'"))
                .unwrap_or_default()
        ));
    }
    if let Some(s) = info.start_func {
        notes.push(format!("start function index {s}"));
    }
    if !info.other_imports.is_empty() {
        let mut counts = std::collections::BTreeMap::new();
        for k in &info.other_imports {
            *counts.entry(*k).or_insert(0usize) += 1;
        }
        let summary = counts
            .into_iter()
            .map(|(k, n)| format!("{n} {k}"))
            .collect::<Vec<_>>()
            .join(", ");
        notes.push(format!("non-function imports: {summary}"));
    }
    if !info.memories.is_empty() {
        let total: u64 = info
            .memories
            .iter()
            .map(|(min, _)| *min as u64)
            .sum::<u64>()
            .max(info.memories.len() as u64);
        notes.push(format!(
            "memory: {} module(s), {} page(s) minimum (64 KiB each)",
            info.memories.len(),
            total
        ));
    }

    // Function symbols carry real names when the `name` custom section
        // has a function map (wasm-bindgen keeps it), and every body carries
        // its declared size. Defined functions index from the import count.
        // Exported functions take their export name when the name section did
        // not name them — for bindgen builds the export names are the ones an
        // analyst actually searches for (classify, workbenchengine_*).
        let import_count = info.import_funcs.len() as u32;
        let mut export_names: std::collections::BTreeMap<u32, String> = Default::default();
        for (kind, idx, name) in &info.export_kinds {
            if *kind == "func" {
                export_names.entry(*idx).or_insert_with(|| name.clone());
            }
        }
        let bin = Binary {
        path: path.to_string(),
        size: bytes.len() as u64,
        format: Format::Wasm,
        arch: Arch::Wasm,
        bits: 32,
        endian_little: true,
        is_lib: true,
        is_stripped: info.func_names.is_empty(),
        // `entry` carries the start function *index* — wasm has no native
        // entry address. The note above says so.
        entry: info.start_func.map(|s| s as u64).unwrap_or(0),
        image_base: 0,
        subsystem: None,
        timestamp: None,
        sections: model_sections,
        imports,
        exports: info.exports,
        symbols: info
            .func_bodies
            .iter()
            .enumerate()
            .map(|(k, (off, size))| {
                let idx = import_count + k as u32;
                let name = info
                    .func_names
                    .iter()
                    .find(|(i, _)| *i == idx)
                    .map(|(_, n)| n.clone())
                    .or_else(|| export_names.get(&idx).cloned())
                    .unwrap_or_default();
                Symbol {
                    addr: *off,
                    name,
                    kind: SymKind::Func,
                    size: Some(*size),
                }
            })
            .collect(),
        func_hints: info.func_bodies.iter().map(|(off, _)| *off).collect(),
        libs,
        pointer_map: info
            .data_ranges
            .iter()
            .map(|(mem, file, len)| crate::model::PointerRange {
                mem: *mem,
                file: *file,
                len: *len,
            })
            .collect(),
        rpaths: Vec::new(),
        overall_entropy: 0.0,
        overlay_off: None,
        overlay_size: 0,
        overlay_entropy: 0.0,
        has_signature: false,
        sig_region: None,
        hardening: Default::default(),
        pdb: crate::formats::pdbsym::Pdb::NotReferenced,
        notes,
    };
    Ok(bin)
}

// ── fixtures + tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod fixture_bytes {
    //! Hand-assembled module bytes for the tests: a minimal module and one
    //! shaped like the modules wasm-bindgen emits. Small enough to read as a
    //! spec walk-through, so regressions point at the exact feature.
    use super::*;

    /// LEB128 encoding for fixture construction.
    pub fn uleb(n: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = n;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }

    pub fn named(s: &str) -> Vec<u8> {
        let mut out = uleb(s.len() as u32);
        out.extend_from_slice(s.as_bytes());
        out
    }

    pub fn section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(uleb(payload.len() as u32));
        out.extend_from_slice(payload);
        out
    }

    /// A minimal module: one type, one function, one export, no code (the code
    /// section is an empty vec of bodies, which is well-formed).
    pub fn wasm_minimal() -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // type: [] -> []
        out.extend(section(SEC_TYPE, &[0x01, 0x60, 0x00, 0x00]));
        // function: func 0 : type 0
        out.extend(section(SEC_FUNCTION, &[0x01, 0x00]));
        // export: "run" : func 0
        let mut exp = vec![0x01];
        exp.extend(named("run"));
        exp.extend([0x00, 0x00]);
        out.extend(section(SEC_EXPORT, &exp));
        // code: one empty body (just `end`)
        out.extend(section(SEC_CODE, &[0x01, 0x02, 0x00, 0x0B]));
        out
    }

    /// A module shaped like the ones wasm-bindgen emits: a custom `producers`
    /// section, a `wbg` import, a memory, an export, and a data segment.
    pub fn wasm_bindgen_like() -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // type: (i32) -> ()
        out.extend(section(SEC_TYPE, &[0x01, 0x60, 0x01, 0x7F, 0x00]));
        // import: env."wbg_throw" func : type 0
        let mut imp = vec![0x01];
        imp.extend(named("env"));
        imp.extend(named("wbg_throw"));
        imp.extend([0x00, 0x00]);
        out.extend(section(SEC_IMPORT, &imp));
        // memory: min 1
        out.extend(section(SEC_MEMORY, &[0x01, 0x00, 0x01]));
        // export: "memory" : mem 0, "run" : func 0 (imported funcs are index 0,
        // so the defined func 0 sits at index 1)
        let mut exp = vec![0x02];
        exp.extend(named("memory"));
        exp.extend([0x02, 0x00]);
        exp.extend(named("run"));
        exp.extend([0x00, 0x01]);
        out.extend(section(SEC_EXPORT, &exp));
        // custom "producers": processed-by [walrus 0.24.5]
        let mut prod = named("producers");
        prod.extend(uleb(1));
        prod.extend(named("processed-by"));
        prod.extend(uleb(1));
        prod.extend(named("walrus"));
        prod.extend(named("0.24.5"));
        out.extend(section(SEC_CUSTOM, &prod));
        // code: one body with two locals of i32, then end
        out.extend(section(SEC_CODE, &[0x01, 0x05, 0x01, 0x01, 0x7F, 0x41, 0x00, 0x0B]));
        // data: one active segment into memory 0 at offset 0, 4 bytes
        let mut dat = vec![0x01, 0x00, 0x41, 0x00, 0x0B, 0x04];
        dat.extend_from_slice(b"ABCD");
        out.extend(section(SEC_DATA, &dat));
        out
    }

    /// A module with one exported function exercising the decoder: locals,
/// consts, arithmetic, a memarg load, control flow (if/else/return), so the
/// WAT rendering has real shapes to prove.
    pub fn wasm_wat_demo() -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // type: (i32, i32) -> i32
        out.extend(section(SEC_TYPE, &[0x01, 0x60, 0x02, 0x7F, 0x7F, 0x01, 0x7F]));
        // function: func 0 : type 0
        out.extend(section(SEC_FUNCTION, &[0x01, 0x00]));
        // export: "demo" : func 0
        let mut exp = vec![0x01];
        exp.extend(named("demo"));
        exp.extend([0x00, 0x00]);
        out.extend(section(SEC_EXPORT, &exp));
        // code: body with one extra i32 local, then the demo sequence.
        //   i32.const 16; local.get 0; i32.add; local.set 2
        //   local.get 2; i32.load offset=8
        //   if; local.get 2; return; else; i32.const 42; end; end
        let body: Vec<u8> = [
            &[
                0x01, 0x01, 0x7F, // 1 local group: 1 x i32
                0x41, 0x10, // i32.const 16
                0x20, 0x00, // local.get 0
                0x6A, // i32.add
                0x21, 0x02, // local.set 2
                0x20, 0x02, // local.get 2
                0x28, 0x02, 0x08, // i32.load align=4 offset=8
                0x04, 0x40, // if (void)
                0x20, 0x02, // local.get 2
                0x0F, // return
                0x05, // else
                0x41, 0x2A, // i32.const 42
                0x0B, // end (if)
                0x0B, // end (func)
            ][..],
        ]
        .concat();
        let mut code = vec![0x01];
        code.extend(uleb(body.len() as u32));
        code.extend(body);
        out.extend(section(SEC_CODE, &code));
        out
    }

    /// A minimal module plus a `name` custom section carrying a function-name
    /// map: the shape wasm-bindgen ships, and the reason wasm triage gets real
    /// symbols without a lifter.
    pub fn wasm_named() -> Vec<u8> {
        let mut out = wasm_minimal();
        // name section: module name "m", function 0 -> "the_run"
        let mut ns = named("name");
        let mut module_sub = vec![0x00];
        let module_name = named("m");
        module_sub.extend(uleb(module_name.len() as u32));
        module_sub.extend(module_name);
        let mut func_sub = vec![0x01];
        let mut map = uleb(1);
        map.extend(uleb(0));
        map.extend(named("the_run"));
        func_sub.extend(uleb(map.len() as u32));
        func_sub.extend(map);
        ns.extend(module_sub);
        ns.extend(func_sub);
        out.extend(section(SEC_CUSTOM, &ns));
        out
    }

    /// A data section whose segment loads at a realistic address and whose
/// payload ends with a planted (pointer, length) pair aimed at the string:
/// the slice-table shape `resolve_pointers` exists for, with the wasm
/// memory→file translation exercised end to end.
    pub fn wasm_with_slice_table() -> Vec<u8> {
        let mut out = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        // data: one active segment at memory 0x100000 (the wasm-bindgen load
        // base; sleb128 80 80 C0 00), 4 bytes "ABCD", then the (ptr,len) pair
        // as an image pointer. Section layout: id@8, size@9, payload@10.. =
        // [01 00 41 80 80 C0 00 0B 04 41 42 43 44] (13 B) + pair (8 B).
        let mut dat = vec![0x01, 0x00, 0x41, 0x80, 0x80, 0xC0, 0x00, 0x0B, 0x04];
        dat.extend_from_slice(b"ABCD");
        let abcd_mem: u32 = 0x0010_0000; // load address of the segment = of "ABCD"
        dat.extend_from_slice(&abcd_mem.to_le_bytes());
        dat.extend_from_slice(&4u32.to_le_bytes());
        out.extend(section(SEC_DATA, &dat));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixture_bytes::{wasm_bindgen_like, wasm_minimal};
    use super::*;
    use crate::analysis::entropy;

    #[test]
    fn minimal_module_parses() {
        let bytes = wasm_minimal();
        let bin = build("t.wasm", &bytes).unwrap();
        assert_eq!(bin.format, Format::Wasm);
        assert_eq!(bin.arch, Arch::Wasm);
        assert_eq!(bin.bits, 32);
        assert!(bin.endian_little);
        assert_eq!(bin.exports, vec!["run".to_string()]);
        assert!(bin.imports.is_empty());
        // type, function, export, code
        assert_eq!(bin.sections.len(), 4);
        assert_eq!(bin.func_hints.len(), 1);
        // Identity map: body = payload(29) + count byte + size byte = 31.
        assert_eq!(bin.func_hints[0], 31);
        assert!(bin.is_lib);
        assert!(bin.is_stripped);
        assert!(bin.entry == 0);
    }

    #[test]
    fn bindgen_shape_parses() {
        let bytes = wasm_bindgen_like();
        let bin = build("t.wasm", &bytes).unwrap();
        assert_eq!(bin.imports.len(), 1);
        assert_eq!(bin.imports[0].name, "env");
        assert_eq!(bin.imports[0].functions, vec!["wbg_throw".to_string()]);
        assert_eq!(bin.libs, vec!["env".to_string()]);
        assert_eq!(bin.exports, vec!["memory".to_string(), "run".to_string()]);
        assert!(bin
            .notes
            .iter()
            .any(|n| n.contains("producers: processed-by: walrus 0.24.5")));
        assert!(bin.notes.iter().any(|n| n.contains("memory: 1 module(s)")));
        // Custom section keeps its name in the section table.
        assert!(bin
            .sections
            .iter()
            .any(|s| s.name == "producers" && s.file_size > 0));
        // Data section parsed: one segment, entropy filled from real bytes.
        let data = bin.sections.iter().find(|s| s.name == "data").unwrap();
        assert!(data.entropy > 0.0);
        assert_eq!(data.file_size, 12); // 6 header bytes + 4 payload + section hdr
        // Section entropy must agree with the shared helper.
        assert_eq!(
            data.entropy,
            entropy::entropy(&bytes[data.file_off as usize..(data.file_off + data.file_size) as usize])
        );
        // Declared function (index 1 in the full index space) got a body hint.
        assert_eq!(bin.func_hints.len(), 1);
    }

    #[test]
    fn name_section_gives_named_sized_symbols() {
        let bytes = fixture_bytes::wasm_named();
        let bin = build("t.wasm", &bytes).unwrap();
        assert!(!bin.is_stripped);
        assert_eq!(bin.symbols.len(), 1);
        let s = &bin.symbols[0];
        assert_eq!(s.name, "the_run");
        assert_eq!(s.kind, SymKind::Func);
        assert_eq!(s.addr, 31); // body offset in the minimal layout
        assert_eq!(s.size, Some(2)); // locals-count + `end`
        assert!(bin
            .notes
            .iter()
            .any(|n| n.contains("custom 'name' section: 1 function name(s)")));
    }

    #[test]
    fn slice_table_pair_resolves_through_memory_map() {
        let bytes = fixture_bytes::wasm_with_slice_table();
        let bin = build("t.wasm", &bytes).unwrap();
        // The active segment registered its load address: memory 0x100000 ->
        // file 19, where the "ABCD" bytes live.
        assert_eq!(bin.pointer_map.len(), 1);
        assert_eq!((bin.pointer_map[0].mem, bin.pointer_map[0].file, bin.pointer_map[0].len),
                   (0x100000, 19, 4));
        let refs = crate::analysis::strings::resolve_pointers(&bin, &bytes, 400);
        // The planted pair (mem pointer 0x100000, len 4) resolves through the
        // map to the in-segment string.
        let hit = refs
            .iter()
            .find(|r| r.text == "ABCD")
            .expect("planted slice pair not resolved");
        assert_eq!(hit.target, 19);
        assert_eq!(hit.len, 4);
        assert_eq!(hit.addr, 23); // pair sits right after the string bytes
    }

    #[test]
    fn wat_listing_renders_control_flow_and_memarg() {
        let bytes = fixture_bytes::wasm_wat_demo();
        let bin = build("t.wasm", &bytes).unwrap();
        let listing = crate::analysis::wat::render_function(&bin, &bytes, "demo").unwrap();
        // Header + locals, then the exact instruction sequence with depth.
        assert!(listing.contains("; function demo @"));
        assert!(listing.contains("; locals: 1 i32"));
        assert!(listing.contains("i32.const 16"));
        assert!(listing.contains("local.get 0"));
        assert!(listing.contains("i32.add"));
        assert!(listing.contains("local.set 2"));
        assert!(listing.contains("i32.load offset=8"));
        assert!(listing.contains("if"));
        assert!(listing.contains("  local.get 2")); // inside the if: indented
        assert!(listing.contains("  return"));
        assert!(listing.contains("else"));
        assert!(listing.contains("  i32.const 42"));
        // The final `end` closes the function and there is no partial marker.
        assert!(!listing.contains("; partial"));
        let lines: Vec<&str> = listing.lines().collect();
        assert!(lines.last().unwrap().ends_with("end"));
        // Selector by index and by address resolve to the same function.
        let by_index = crate::analysis::wat::render_function(&bin, &bytes, "0").unwrap();
        let addr = bin.symbols[0].addr;
        let by_addr = crate::analysis::wat::render_function(
            &bin,
            &bytes,
            &format!("{addr:#x}"),
        )
        .unwrap();
        assert_eq!(listing, by_index);
        assert_eq!(listing, by_addr);
    }

    #[test]
    fn wat_listing_marks_unsupported_opcodes_explicitly() {
        let bytes = fixture_bytes::wasm_wat_demo();
        let bin = build("t.wasm", &bytes).unwrap();
        // Corrupt the body's last instruction with SIMD 0xFD: the listing
        // must stop there with a marker, not guess.
        let mut corrupt = bytes.clone();
        let code_sec = corrupt.iter().position(|b| *b == 0x0B).unwrap() - 0; // find end byte
        let _ = code_sec;
        // Locate the body: last two bytes of the file are the two `end`s.
        let n = corrupt.len();
        corrupt[n - 1] = 0xFD;
        let listing = crate::analysis::wat::render_function(&bin, &corrupt, "0").unwrap();
        assert!(listing.contains("; partial: unsupported opcode 0xfd"));
    }

    #[test]
    fn truncated_and_corrupt_files_degrade_without_panicking() {
        let full = wasm_bindgen_like();
        // Every truncation point must produce either a clean error or a
        // degraded-but-complete parse; never a panic.
        for cut in 0..full.len() {
            let bytes = &full[..cut];
            if bytes.len() < 8 || bytes[0..4] != [0x00, 0x61, 0x73, 0x6D] {
                assert!(build("t.wasm", bytes).is_err());
            } else if let Ok(bin) = build("t.wasm", bytes) {
                assert_eq!(bin.format, Format::Wasm);
            }
        }
        // Bad magic under a wasm-sized header.
        let mut bad = full.clone();
        bad[3] = 0x7F;
        assert!(build("t.wasm", &bad).is_err());
        // A section size that lies past EOF is clamped, not trusted.
        let mut lying = wasm_minimal();
        lying[8 + 1] = 0xFF; // blow up the type section's declared size
        let bin = build("t.wasm", &lying).unwrap();
        assert!(!bin.sections.is_empty());
        assert!(bin.notes.iter().any(|n| n.contains("not fully walked")));
    }

    #[test]
    fn garbage_that_happens_to_start_with_magic_stays_bounded() {
        // 64 KiB of random bytes behind the magic: the walk must terminate.
        let mut b = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        b.extend(std::iter::repeat_n(0xA5u8, 64 * 1024));
        let bin = build("t.wasm", &b).unwrap();
        assert_eq!(bin.format, Format::Wasm);
        // The unreadable region after the magic is carved as one section row.
        assert!(bin.sections.iter().any(|s| s.name == "trailing"));
        assert_eq!(
            bin.sections
                .iter()
                .filter(|s| s.name == "trailing")
                .map(|s| s.file_size)
                .sum::<u64>(),
            (b.len() - 8) as u64
        );
    }
}