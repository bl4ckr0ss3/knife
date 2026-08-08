//! AArch64 disassembly, hand-rolled for the lite path.
//!
//! The engine and the linear `dis` command need, per instruction, four things:
//! a length, a flow class, a branch target, and a readable rendering. iced-x86
//! is x86-only, so this module decodes the small ARM64 vocabulary that covers
//! prologues, calls, branches, and the workhorse data instructions — anything
//! else renders as its raw word, which is never a lie. Import veneers
//! (`adrp`/`ldr`/`br` through a GOT page) stay invisible on purpose;
//! resolving those is a later roadmap item.

use iced_x86::FlowControl;

pub const LEN: usize = 4;

/// What one decoded instruction looks like to a consumer.
pub struct Insn {
    pub addr: u64,
    pub len: usize,
    pub flow: FlowControl,
    /// Target of a direct branch or call, if this instruction has one.
    pub target: Option<u64>,
    pub text: String,
}

fn sext(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn normal(addr: u64, text: String) -> Insn {
    Insn {
        addr,
        len: LEN,
        flow: FlowControl::Next,
        target: None,
        text,
    }
}

const COND: [&str; 16] = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
];

fn reg(rd: u64, wide: bool) -> String {
    if wide {
        format!("x{rd}")
    } else {
        format!("w{rd}")
    }
}

/// Decode the instruction whose bytes start at `code` (at least 4 bytes), at
/// `ip`. Invalid or truncated input is `None`.
pub fn decode(code: &[u8], ip: u64) -> Option<Insn> {
    let e: [u8; 4] = code.get(0..4)?.try_into().ok()?;
    let w = u32::from_le_bytes(e);
    let addr = ip;

    // ── direct branches ──
    let top6 = w >> 26;
    if top6 == 0b000101 {
        // B imm26
        let off = sext(u64::from(w & 0x03ff_ffff), 26) << 2;
        let t = addr.wrapping_add_signed(off);
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::UnconditionalBranch,
            target: Some(t),
            text: format!("b       0x{t:x}"),
        });
    }
    if top6 == 0b100101 {
        // BL imm26
        let off = sext(u64::from(w & 0x03ff_ffff), 26) << 2;
        let t = addr.wrapping_add_signed(off);
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::Call,
            target: Some(t),
            text: format!("bl      0x{t:x}"),
        });
    }

    // ── conditional branches ──
    if w & 0xff00_0000 == 0x5400_0000 {
        // B.cond imm19
        let off = sext(u64::from((w >> 5) & 0x7_ffff), 19) << 2;
        let t = addr.wrapping_add_signed(off);
        let cond = COND[(w & 0xf) as usize];
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::ConditionalBranch,
            target: Some(t),
            text: format!("b.{cond}   0x{t:x}"),
        });
    }
    if w & 0x7f00_0000 == 0x3400_0000 {
        // CBZ/CBNZ (wide iff bit 31)
        let mn = if w & 0x0100_0000 != 0 { "cbnz" } else { "cbz" };
        let off = sext(u64::from((w >> 5) & 0x7_ffff), 19) << 2;
        let t = addr.wrapping_add_signed(off);
        let rd = u64::from(w & 0x1f);
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::ConditionalBranch,
            target: Some(t),
            text: format!("{mn} x{rd}, 0x{t:x}"),
        });
    }
    if (w & 0xff00_0000) == 0xcc00_0000 || (w & 0xff00_0000) == 0xcd00_0000 {
        // TBZ / TBNZ b5, imm14
        let op = if w & 0x0100_0000 != 0 { "tbnz" } else { "tbz" };
        let off = sext(u64::from((w >> 5) & 0x3fff), 14) << 2;
        let t = addr.wrapping_add_signed(off);
        let rd = u64::from(w & 0x1f);
        let bit = u64::from(((w >> 19) & 0x1f) | ((w >> 5) >> 26));
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::ConditionalBranch,
            target: Some(t),
            text: format!("{op} x{rd}, #{bit}, 0x{t:x}"),
        });
    }

    // ── register branches ──
    if w & 0xffff_fc1f == 0xd61f_0000 {
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::IndirectBranch,
            target: None,
            text: format!("br      x{}", (w >> 5) & 0x1f),
        });
    }
    if w & 0xffff_fc1f == 0xd63f_0000 {
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::IndirectCall,
            target: None,
            text: format!("blr     x{}", (w >> 5) & 0x1f),
        });
    }
    if w & 0xffff_fc1f == 0xd65f_0000 {
        // RET
        let r = (w >> 5) & 0x1f;
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::Return,
            target: None,
            text: if r == 0x1e {
                "ret".to_string()
            } else {
                format!("ret     x{r}")
            },
        });
    }

    // ── system ──
    if (w & 0xffe0_0000) == 0xd400_0000 {
        // SVC / HVC / SMC
        return Some(Insn {
            addr,
            len: LEN,
            flow: FlowControl::Interrupt,
            target: None,
            text: format!("svc     #{:x}", w & 0xffff),
        });
    }

    // ── address literals ──
    if (w & 0x9f00_0000) == 0x9000_0000 || (w & 0x9f00_0000) == 0x1000_0000 {
        let is_adrp = w & 0x8000_0000 != 0;
        let immhi = u64::from((w >> 5) & 0x7_ffff);
        let immlo = u64::from((w >> 29) & 0x3);
        // The 21-bit signed immediate is immhi:immlo. adr adds it to PC as a
        // byte offset; adrp shifts it by a page and adds it to Align(PC, 4096).
        // Both are measured from the instruction itself, not the next one.
        let imm21 = sext((immhi << 2) | immlo, 21);
        let rd = u64::from(w & 0x1f);
        let text = if is_adrp {
            let t = (addr & !0xfff).wrapping_add_signed(imm21 << 12);
            format!("adrp    x{rd}, 0x{t:x}")
        } else {
            let t = addr.wrapping_add_signed(imm21);
            format!("adr     x{rd}, 0x{t:x}")
        };
        return Some(normal(addr, text));
    }

    // ── movz / movn / movk ──
    if (w & 0x7fa0_0000) == 0x5280_0000
        || (w & 0x7fa0_0000) == 0x1280_0000
        || (w & 0x7fa0_0000) == 0x7280_0000
    {
        let wide = w & 0x8000_0000 != 0;
        let rd = u64::from(w & 0x1f);
        let imm = (w >> 5) & 0xffff;
        let hw = (w >> 21) & 0x3;
        let mnem = if (w & 0x7fa0_0000) == 0x5280_0000 {
            "movz"
        } else if (w & 0x7fa0_0000) == 0x1280_0000 {
            "movn"
        } else {
            "movk"
        };
        let mut text = format!("{mnem}    {}, #{imm:#x}", reg(rd, wide));
        if hw != 0 {
            text.push_str(&format!(", lsl #{hw}"));
        }
        return Some(normal(addr, text));
    }

    // ── the add/sub immediate family (the prologue's spine) ──
    if (w & 0x1e00_0000) == 0x1000_0000 {
        let wide = w & 0x8000_0000 != 0;
        let sub = w & 0x4000_0000 != 0;
        let mnem = match ((w >> 30) & 1 == 0, sub) {
            (true, false) => "add",
            (true, true) => "sub",
            (false, false) => "adds",
            (false, true) => "subs",
        };
        let rd = u64::from(w & 0x1f);
        let rn = u64::from((w >> 5) & 0x1f);
        let imm = u64::from((w >> 10) & 0xfff);
        let shift = if w & 0x0040_0000 != 0 { 12 } else { 0 };
        return Some(normal(
            addr,
            format!(
                "{mnem:<8}{}, {}, #{shift_imm}",
                reg(rd, wide),
                reg(rn, wide),
                shift_imm = if shift == 12 {
                    imm.checked_shl(12).unwrap_or(0).to_string() + ", lsl #12"
                } else {
                    imm.to_string()
                },
            ),
        ));
    }

    // ── add/sub shifted-register (the accumulator of prologue arith) ──
    if (w & 0x1ff0_0000) == 0x0b00_0000 && (w & 0x0060_0000) == 0 {
        let wide = w & 0x8000_0000 != 0;
        let sub = w & 0x4000_0000 != 0;
        let mnem = match ((w >> 30) & 1 == 0, sub) {
            (true, false) => "add",
            (true, true) => "sub",
            (false, false) => "adds",
            (false, true) => "subs",
        };
        let rd = u64::from(w & 0x1f);
        let rn = u64::from((w >> 5) & 0x1f);
        let rm = u64::from((w >> 16) & 0x1f);
        return Some(normal(
            addr,
            format!(
                "{mnem:<8}{}, {}, {}",
                reg(rd, wide),
                reg(rn, wide),
                reg(rm, wide)
            ),
        ));
    }

    // ── ldr/str with an immediate offset (the workhorse load) ──
    if (w & 0xffc0_0000) == 0xf940_0000 || (w & 0xffc0_0000) == 0xf900_0000 {
        let wide = true;
        let store = w & 0x0040_0000 == 0;
        let rt = u64::from(w & 0x1f);
        let rn = u64::from((w >> 5) & 0x1f);
        let imm = u64::from((w >> 10) & 0xfff) << 3;
        let mnem = if store { "str" } else { "ldr" };
        return Some(normal(
            addr,
            format!("{mnem:<8}{}, [{}, #{imm}]", reg(rt, wide), reg(rn, wide)),
        ));
    }

    // ── the register-register orr ──
    if (w & 0x7fe0_0000) == 0x2a00_0000 {
        let wide = w & 0x8000_0000 != 0;
        let rd = u64::from(w & 0x1f);
        let rn = u64::from((w >> 5) & 0x1f);
        let rm = u64::from((w >> 16) & 0x1f);
        return Some(normal(
            addr,
            format!(
                "orr     {}, {}, {}",
                reg(rd, wide),
                reg(rn, wide),
                reg(rm, wide)
            ),
        ));
    }

    // ── nop / hint space ──
    if w == 0xd503_201f {
        return Some(normal(addr, "nop".to_string()));
    }

    // ── everything else renders as its raw word: truthful, not invented ──
    Some(normal(addr, format!("dword    0x{w:08x}")))
}

/// A fallback renderer for bytes we were unable to classify: always truthful,
/// never invented.
pub fn text(bytes: &[u8], ip: u64) -> String {
    decode(bytes, ip)
        .map(|i| i.text)
        .unwrap_or_else(|| "??".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(w: u32, ip: u64) -> Insn {
        decode(&w.to_le_bytes(), ip).unwrap()
    }

    #[test]
    fn bl_is_a_call_with_a_pc_relative_target() {
        // bl +0x20 at 0x1000 → 0x1020
        let w = 0x9400_0008; // BL imm26 = 8 → 8*4 = 0x20
        let i = dec(w, 0x1000);
        assert_eq!(i.flow, FlowControl::Call);
        assert_eq!(i.target, Some(0x1020));
    }

    #[test]
    fn a_backward_branch_sign_extends() {
        // b -0x10 at 0x1000 → 0xff0
        let off = -4i32 as u32 & 0x03ff_ffff; // -4 words = -0x10 bytes
        let w = 0x1400_0000 | off;
        let i = dec(w, 0x1000);
        assert_eq!(i.flow, FlowControl::UnconditionalBranch);
        assert_eq!(i.target, Some(0xff0));
    }

    #[test]
    fn adr_is_pc_relative_with_no_scaling() {
        // adr x0, PC+4: imm21 = 4, no shift, no +4. At 0x1000 → 0x1004.
        // encode immlo=bits[30:29], immhi=bits[23:5]
        let imm = 4u32;
        let immlo = imm & 3;
        let immhi = (imm >> 2) & 0x7ffff;
        let w = 0x1000_0000 | (immlo << 29) | (immhi << 5); // rd = x0
        let i = dec(w, 0x1000);
        assert_eq!(i.text, "adr     x0, 0x1004");
    }

    #[test]
    fn adrp_aligns_pc_to_a_page_before_adding() {
        // adrp x0, +1 page from a pc that is NOT page-aligned. The result must
        // be Align(pc,4096) + 0x1000, independent of the low bits of pc.
        let imm = 1u32; // one page
        let immlo = imm & 3;
        let immhi = (imm >> 2) & 0x7ffff;
        let w = 0x9000_0000 | (immlo << 29) | (immhi << 5); // rd = x0
        let i = dec(w, 0x1abc);
        assert_eq!(i.text, "adrp    x0, 0x2000", "Align(0x1abc,4096)+0x1000");
    }

    #[test]
    fn ret_and_blr_classify_as_flow() {
        assert_eq!(dec(0xd65f_03c0, 0).flow, FlowControl::Return);
        assert_eq!(dec(0xd63f_0000, 0).flow, FlowControl::IndirectCall);
        assert_eq!(dec(0xd61f_0000, 0).flow, FlowControl::IndirectBranch);
    }
}
