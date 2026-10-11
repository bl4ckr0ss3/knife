//! WAT-style listing for WebAssembly function bodies.
//!
//! This is the wasm counterpart of the native disassembler: a linear,
//! depth-aware decode of one function body into readable instructions. It is
//! deliberately *not* an analysis pass — no CFG, no stack modeling — the same
//! way `knife dis` listing rows are not the pseudocode pass. Coverage is the
//! core spec plus the `0xFC` misc prefix; anything else renders as a partial
//! listing with an explicit marker rather than a guess.
//!
//! Addresses are file offsets (the wasm identity map), matching the symbol
//! addresses `formats::wasm` produces, so cross-references between the two
//! stay meaningful.

use crate::model::Binary;
use anyhow::{anyhow, Result};

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
    fn sleb(&mut self) -> Option<i64> {
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
}

fn valtype_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x7f => "i32",
        0x7e => "i64",
        0x7d => "f32",
        0x7c => "f64",
        0x7b => "v128",
        0x70 => "funcref",
        0x6f => "externref",
        _ => return None,
    })
}

/// Block/loop/if type operand: 0x40 = void, a valtype byte = one result, or
/// an s33 type index for multi-value signatures.
fn blocktype(c: &mut Cur) -> Option<String> {
    let b = c.u8()?;
    if b == 0x40 {
        return Some(String::new());
    }
    if let Some(name) = valtype_name(b) {
        return Some(format!(" (result {name})"));
    }
    let idx = c.sleb()?;
    Some(format!(" (type {idx})"))
}

/// memarg: alignment and offset. Default alignment/offset print as nothing,
/// matching WAT.
fn memarg(c: &mut Cur) -> Option<String> {
    let align = c.uleb()?;
    let offset = c.uleb()?;
    if offset == 0 && align <= 2 {
        return Some(String::new());
    }
    let mut s = String::new();
    if offset != 0 {
        s.push_str(&format!(" offset={offset}"));
    }
    if align > 2 {
        s.push_str(&format!(" align={}", 1u32 << align.min(31)));
    }
    Some(s)
}

fn load_store_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x28 => "i32.load",
        0x29 => "i64.load",
        0x2a => "f32.load",
        0x2b => "f64.load",
        0x2c => "i32.load8_s",
        0x2d => "i32.load8_u",
        0x2e => "i32.load16_s",
        0x2f => "i32.load16_u",
        0x30 => "i64.load8_s",
        0x31 => "i64.load8_u",
        0x32 => "i64.load16_s",
        0x33 => "i64.load16_u",
        0x34 => "i64.load32_s",
        0x35 => "i64.load32_u",
        0x36 => "i32.store",
        0x37 => "i64.store",
        0x38 => "f32.store",
        0x39 => "f64.store",
        0x3a => "i32.store8",
        0x3b => "i32.store16",
        0x3c => "i64.store8",
        0x3d => "i64.store16",
        0x3e => "i64.store32",
        _ => return None,
    })
}

/// Numeric/comparison opcodes (0x45..=0xC4) carry no immediates; the name is
/// the whole instruction.
fn numeric_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x45 => "i32.eqz",
        0x46 => "i32.eq",
        0x47 => "i32.ne",
        0x48 => "i32.lt_s",
        0x49 => "i32.lt_u",
        0x4a => "i32.gt_s",
        0x4b => "i32.gt_u",
        0x4c => "i32.le_s",
        0x4d => "i32.le_u",
        0x4e => "i32.ge_s",
        0x4f => "i32.ge_u",
        0x50 => "i64.eqz",
        0x51 => "i64.eq",
        0x52 => "i64.ne",
        0x53 => "i64.lt_s",
        0x54 => "i64.lt_u",
        0x55 => "i64.gt_s",
        0x56 => "i64.gt_u",
        0x57 => "i64.le_s",
        0x58 => "i64.le_u",
        0x59 => "i64.ge_s",
        0x5a => "i64.ge_u",
        0x5b => "f32.eq",
        0x5c => "f32.ne",
        0x5d => "f32.lt",
        0x5e => "f32.gt",
        0x5f => "f32.le",
        0x60 => "f32.ge",
        0x61 => "f64.eq",
        0x62 => "f64.ne",
        0x63 => "f64.lt",
        0x64 => "f64.gt",
        0x65 => "f64.le",
        0x66 => "f64.ge",
        0x67 => "i32.clz",
        0x68 => "i32.ctz",
        0x69 => "i32.popcnt",
        0x6a => "i32.add",
        0x6b => "i32.sub",
        0x6c => "i32.mul",
        0x6d => "i32.div_s",
        0x6e => "i32.div_u",
        0x6f => "i32.rem_s",
        0x70 => "i32.rem_u",
        0x71 => "i32.and",
        0x72 => "i32.or",
        0x73 => "i32.xor",
        0x74 => "i32.shl",
        0x75 => "i32.shr_s",
        0x76 => "i32.shr_u",
        0x77 => "i32.rotl",
        0x78 => "i32.rotr",
        0x79 => "i64.clz",
        0x7a => "i64.ctz",
        0x7b => "i64.popcnt",
        0x7c => "i64.add",
        0x7d => "i64.sub",
        0x7e => "i64.mul",
        0x7f => "i64.div_s",
        0x80 => "i64.div_u",
        0x81 => "i64.rem_s",
        0x82 => "i64.rem_u",
        0x83 => "i64.and",
        0x84 => "i64.or",
        0x85 => "i64.xor",
        0x86 => "i64.shl",
        0x87 => "i64.shr_s",
        0x88 => "i64.shr_u",
        0x89 => "i64.rotl",
        0x8a => "i64.rotr",
        0x8b => "f32.abs",
        0x8c => "f32.neg",
        0x8d => "f32.ceil",
        0x8e => "f32.floor",
        0x8f => "f32.trunc",
        0x90 => "f32.nearest",
        0x91 => "f32.sqrt",
        0x92 => "f32.add",
        0x93 => "f32.sub",
        0x94 => "f32.mul",
        0x95 => "f32.div",
        0x96 => "f32.min",
        0x97 => "f32.max",
        0x98 => "f32.copysign",
        0x99 => "f64.abs",
        0x9a => "f64.neg",
        0x9b => "f64.ceil",
        0x9c => "f64.floor",
        0x9d => "f64.trunc",
        0x9e => "f64.nearest",
        0x9f => "f64.sqrt",
        0xa0 => "f64.add",
        0xa1 => "f64.sub",
        0xa2 => "f64.mul",
        0xa3 => "f64.div",
        0xa4 => "f64.min",
        0xa5 => "f64.max",
        0xa6 => "f64.copysign",
        0xa7 => "i32.wrap_i64",
        0xa8 => "i32.trunc_f32_s",
        0xa9 => "i32.trunc_f32_u",
        0xaa => "i32.trunc_f64_s",
        0xab => "i32.trunc_f64_u",
        0xac => "i64.extend_i32_s",
        0xad => "i64.extend_i32_u",
        0xae => "i64.trunc_f32_s",
        0xaf => "i64.trunc_f32_u",
        0xb0 => "i64.trunc_f64_s",
        0xb1 => "i64.trunc_f64_u",
        0xb2 => "f32.convert_i32_s",
        0xb3 => "f32.convert_i32_u",
        0xb4 => "f32.convert_i64_s",
        0xb5 => "f32.convert_i64_u",
        0xb6 => "f32.demote_f64",
        0xb7 => "f64.convert_i32_s",
        0xb8 => "f64.convert_i32_u",
        0xb9 => "f64.convert_i64_s",
        0xba => "f64.convert_i64_u",
        0xbb => "f64.promote_f32",
        0xbc => "i32.reinterpret_f32",
        0xbd => "i64.reinterpret_f64",
        0xbe => "f32.reinterpret_i32",
        0xbf => "f64.reinterpret_i64",
        0xc0 => "i32.extend8_s",
        0xc1 => "i32.extend16_s",
        0xc2 => "i64.extend8_s",
        0xc3 => "i64.extend16_s",
        0xc4 => "i64.extend32_s",
        _ => return None,
    })
}

fn trunc_sat_name(sub: u32) -> Option<&'static str> {
    Some(match sub {
        0 => "i32.trunc_sat_f32_s",
        1 => "i32.trunc_sat_f32_u",
        2 => "i32.trunc_sat_f64_s",
        3 => "i32.trunc_sat_f64_u",
        4 => "i64.trunc_sat_f32_s",
        5 => "i64.trunc_sat_f32_u",
        6 => "i64.trunc_sat_f64_s",
        7 => "i64.trunc_sat_f64_u",
        _ => return None,
    })
}

/// One decoded instruction.
struct Insn {
    off: usize,
    text: String,
    /// Depth delta: +1 for block/loop/if, -1 for end, 0 otherwise.
    delta: i32,
}

/// Decode one instruction at the cursor. `Err(op)` means "unhandled opcode":
/// the caller stops the listing there with an explicit marker.
fn decode(c: &mut Cur) -> Option<Result<Insn, u8>> {
    let off = c.p;
    macro_rules! insn {
        ($delta:expr, $($arg:tt)*) => {
            Some(Ok(Insn { off, text: format!($($arg)*), delta: $delta }))
        };
    }
    let op = c.u8()?;
    match op {
        0x00 => insn!(0, "unreachable"),
        0x01 => insn!(0, "nop"),
        0x02 => {
            let t = blocktype(c)?;
            insn!(1, "block{}", t)
        }
        0x03 => {
            let t = blocktype(c)?;
            insn!(1, "loop{}", t)
        }
        0x04 => {
            let t = blocktype(c)?;
            insn!(1, "if{}", t)
        }
        0x05 => insn!(0, "else"),
        0x0b => insn!(-1, "end"),
        0x0c => {
            let l = c.uleb()?;
            insn!(0, "br {}", l)
        }
        0x0d => {
            let l = c.uleb()?;
            insn!(0, "br_if {}", l)
        }
        0x0e => {
            let n = c.uleb()?;
            let mut labels = Vec::new();
            for _ in 0..n.min(1024) {
                labels.push(c.uleb()?);
            }
            let default = c.uleb()?;
            if labels.is_empty() {
                insn!(0, "br_table {default}")
            } else {
                let list: Vec<String> = labels.iter().map(|l| l.to_string()).collect();
                insn!(0, "br_table {} {default}", list.join(" "))
            }
        }
        0x0f => insn!(0, "return"),
        0x10 => {
            let f = c.uleb()?;
            insn!(0, "call {f}")
        }
        0x11 => {
            let t = c.uleb()?;
            let tbl = c.uleb()?;
            if tbl == 0 {
                insn!(0, "call_indirect (type {t})")
            } else {
                insn!(0, "call_indirect (type {t}) table {tbl}")
            }
        }
        0x1a => insn!(0, "drop"),
        0x1b => insn!(0, "select"),
        0x1c => {
            let n = c.uleb()?;
            let mut tys = Vec::new();
            for _ in 0..n.min(8) {
                let t = c.u8()?;
                tys.push(valtype_name(t)?.to_string());
            }
            insn!(0, "select (result {})", tys.join(" "))
        }
        0x20 => {
            let i = c.uleb()?;
            insn!(0, "local.get {i}")
        }
        0x21 => {
            let i = c.uleb()?;
            insn!(0, "local.set {i}")
        }
        0x22 => {
            let i = c.uleb()?;
            insn!(0, "local.tee {i}")
        }
        0x23 => {
            let i = c.uleb()?;
            insn!(0, "global.get {i}")
        }
        0x24 => {
            let i = c.uleb()?;
            insn!(0, "global.set {i}")
        }
        0x25 => {
            let i = c.uleb()?;
            insn!(0, "table.get {i}")
        }
        0x26 => {
            let i = c.uleb()?;
            insn!(0, "table.set {i}")
        }
        0x28..=0x3e => {
            let m = memarg(c)?;
            insn!(0, "{}{m}", load_store_name(op)?)
        }
        0x3f => {
            let m = c.u8()?;
            insn!(0, "memory.size {m}")
        }
        0x40 => {
            let m = c.u8()?;
            insn!(0, "memory.grow {m}")
        }
        0x41 => {
            let v = c.sleb()?;
            insn!(0, "i32.const {v}")
        }
        0x42 => {
            let v = c.sleb()?;
            insn!(0, "i64.const {v}")
        }
        0x43 => {
            let raw = c.bytes(4)?;
            insn!(0, "f32.const {}", f32::from_le_bytes(raw.try_into().ok()?))
        }
        0x44 => {
            let raw = c.bytes(8)?;
            insn!(0, "f64.const {}", f64::from_le_bytes(raw.try_into().ok()?))
        }
        0x45..=0xc4 => {
            let name = numeric_name(op)?;
            insn!(0, "{name}")
        }
        0xd0 => {
            let t = c.u8()?;
            insn!(0, "ref.null {}", valtype_name(t).unwrap_or("unknown_ref"))
        }
        0xd1 => insn!(0, "ref.is_null"),
        0xd2 => {
            let f = c.uleb()?;
            insn!(0, "ref.func {f}")
        }
        0xfc => {
            let sub = c.uleb()?;
            let text = match sub {
                0..=7 => trunc_sat_name(sub)?.to_string(),
                8 => {
                    let d = c.uleb()?;
                    let m = c.u8()?;
                    format!("memory.init {d} {m}")
                }
                9 => {
                    let d = c.uleb()?;
                    format!("data.drop {d}")
                }
                10 => {
                    c.u8()?;
                    c.u8()?;
                    "memory.copy".to_string()
                }
                11 => {
                    c.u8()?;
                    "memory.fill".to_string()
                }
                12 => {
                    let a = c.uleb()?;
                    let t = c.uleb()?;
                    format!("table.init {a} {t}")
                }
                13 => {
                    let e = c.uleb()?;
                    format!("elem.drop {e}")
                }
                14 => {
                    let a = c.uleb()?;
                    let b = c.uleb()?;
                    format!("table.copy {a} {b}")
                }
                15 => {
                    let t = c.uleb()?;
                    format!("table.grow {t}")
                }
                16 => {
                    let t = c.uleb()?;
                    format!("table.size {t}")
                }
                17 => {
                    let t = c.uleb()?;
                    format!("table.fill {t}")
                }
                _ => return Some(Err(op)),
            };
            insn!(0, "{text}")
        }
        0xfd => Some(Err(0xfd)), // SIMD: acknowledged gap, explicit marker
        _ => Some(Err(op)),
    }
}

/// Resolve a selector (name, decimal defined-function index, or hex address)
/// to `(addr, size, label)` from the container's symbol facts. `0x…` is an
/// address; bare decimals are indices (they would rarely be valid addresses).
pub fn resolve_function(bin: &Binary, selector: &str) -> Result<(u64, u64, String)> {
    let sel = selector.trim();
    if let Some(hex) = sel.strip_prefix("0x").or_else(|| sel.strip_prefix("0X")) {
        let addr = u64::from_str_radix(hex, 16).map_err(|_| anyhow!("bad address '{sel}'"))?;
        for s in &bin.symbols {
            if s.addr == addr {
                let name = if s.name.is_empty() {
                    format!("sub_{addr:x}")
                } else {
                    s.name.clone()
                };
                return Ok((addr, s.size.unwrap_or(0), name));
            }
        }
        return Err(anyhow!("no wasm function at {sel}"));
    }
    if !sel.is_empty() && sel.chars().all(|c| c.is_ascii_digit()) {
        let idx: usize = sel.parse()?;
        return match bin.symbols.get(idx) {
            Some(s) => {
                let name = if s.name.is_empty() {
                    format!("sub_{:x}", s.addr)
                } else {
                    s.name.clone()
                };
                Ok((s.addr, s.size.unwrap_or(0), name))
            }
            None => Err(anyhow!(
                "function index {idx} out of range ({} defined)",
                bin.symbols.len()
            )),
        };
    }
    for s in &bin.symbols {
        if s.name == sel {
            return Ok((s.addr, s.size.unwrap_or(0), s.name.clone()));
        }
    }
    Err(anyhow!("no wasm function named '{sel}'"))
}

/// Render one function body as a WAT-style listing.
pub fn render_function(bin: &Binary, bytes: &[u8], selector: &str) -> Result<String> {
    let (addr, size, label) = resolve_function(bin, selector)?;
    if size == 0 || addr as usize + size as usize > bytes.len() {
        return Err(anyhow!("function {label}: body out of bounds"));
    }
    let body = &bytes[addr as usize..(addr + size) as usize];
    let mut c = Cur::new(body);

    // Locals declarations: vec of (count, valtype).
    let mut local_desc = Vec::new();
    let Some(groups) = c.uleb() else {
        return Err(anyhow!("function {label}: truncated locals declaration"));
    };
    for _ in 0..groups {
        let Some(n) = c.uleb() else {
            return Err(anyhow!("function {label}: truncated locals declaration"));
        };
        let Some(t) = c.u8() else {
            return Err(anyhow!("function {label}: truncated locals declaration"));
        };
        let name = valtype_name(t)
            .ok_or_else(|| anyhow!("function {label}: unsupported local type {t:#x}"))?;
        local_desc.push(format!("{n} {name}"));
    }

    let mut out = format!("; function {label} @ {addr:#x} ({size} bytes)\n");
    if !local_desc.is_empty() {
        out.push_str(&format!("; locals: {}\n", local_desc.join(", ")));
    }

    // The function body is itself the outermost block: depth 1 now, and the
    // `end` that returns depth to 0 is the one that closes the function.
    let mut depth = 1usize;
    let mut closed = false;
    let mut partial: Option<String> = None;
    while c.p < body.len() {
        match decode(&mut c) {
            Some(Ok(insn)) => {
                let pad_level = depth.saturating_sub(1);
                if insn.delta < 0 {
                    depth = depth.saturating_sub(1);
                }
                let pad = "  ".repeat(pad_level.min(16));
                out.push_str(&format!(
                    "{:06x}: {}{}\n",
                    addr as usize + insn.off,
                    pad,
                    insn.text
                ));
                if insn.delta > 0 {
                    depth += 1;
                }
                if insn.delta < 0 && depth == 0 {
                    closed = true;
                    break;
                }
            }
            Some(Err(op)) => {
                partial = Some(format!("unsupported opcode {op:#04x} at +{:#x}", c.p - 1));
                break;
            }
            None => {
                partial = Some(format!("truncated instruction at +{:#x}", c.p));
                break;
            }
        }
    }
    if !closed && partial.is_none() {
        partial = Some("body exhausted without a closing `end`".into());
    }
    if let Some(p) = partial {
        out.push_str(&format!("; partial: {p}\n"));
    }
    Ok(out)
}