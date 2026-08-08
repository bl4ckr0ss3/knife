//! FLIRT-lite: identify library functions by their machine-code shape.
//!
//! A real FLIRT signature couples a nibble-level prologue mask with a CRC of
//! the function body so that a wrong-size or mis-compiled match is rejected.
//! "Lite" keeps the first half and drops the second: the masks here match
//! instructions whose encodings do not change with offsets or addresses
//! (displacements stay `0x00` = wildcard), which is stable enough for the
//! handful of CRT/compiler-rt helpers that are worth naming. A nameless
//! function that matches is given the helper's name instead of `sub_xxxx`.

/// A function signature: a name plus a byte mask, FLIRT convention — `0x00`
/// means "any byte", `0xFF` means "must equal the pattern byte". Matched at
/// the function's entry point.
pub struct Sig {
    pub name: &'static str,
    /// Functions smaller than this (in bytes, decoded span) are never
    /// matchable; most of these helpers are well under a property boundary.
    pub min_size: usize,
    pub mask: &'static [u8],
}

/// Identify the function at file offset `off` (span `size` bytes).
pub fn identify(bytes: &[u8], off: usize, size: usize) -> Option<&'static str> {
    for sig in SIGS {
        if size < sig.min_size || off + sig.mask.len() > bytes.len() {
            continue;
        }
        let window = &bytes[off..off + sig.mask.len()];
        if window
            .iter()
            .zip(sig.mask.iter())
            .all(|(b, m)| *m == 0 || b == m)
        {
            return Some(sig.name);
        }
    }
    None
}

const fn s(name: &'static str, min_size: usize, mask: &'static [u8]) -> Sig {
    Sig {
        name,
        min_size,
        mask,
    }
}

/// 0x00 bytes inside a mask are wildcards (not zeroes), so zero bytes in a
/// pattern must be written explicitly as a mask with the byte itself...
/// no: a `0x00` mask byte means "any", which is what displacement slots are.
const SIGS: &[Sig] = &[
    // ── MSVC x64: __security_check_cookie ────────────────────────────────
    // mov rcx, [rip+cookie] ; mov rax, [rsp?]... canonical form:
    //   mov rax, qword ptr cs:__security_cookie (48 8b 05 rel32)
    //   cmp rax, qword ptr [rsp]            (48 3b 04 24)
    //   jne +2                              (75 02)
    //   ret                                 (f3 c3, rep ret)
    s(
        "__security_check_cookie",
        15,
        &[
            0x48, 0x8b, 0x05, 0, 0, 0, 0, // mov rax,[rip+cookie]
            0x48, 0x3b, 0x04, 0x24, // cmp rax,[rsp]
            0x75, 0x02, 0xf3, 0xc3,
        ],
    ),
    // x64 variant that begins by copying the cookie out of rcx-equivalent...
    // actually the second-generation form:
    //   mov rax,[rip+cookie] (48 8b 05 rel32); cmp rax, rcx (48 3b c1);
    //   jne +2; ret
    s(
        "__security_check_cookie",
        15,
        &[
            0x48, 0x8b, 0x05, 0, 0, 0, 0, 0x48, 0x3b, 0xc1, 0x75, 0x02, 0xf3, 0xc3,
        ],
    ),
    // ── x86: __security_check_cookie ─────────────────────────────────────
    //   cmp ecx, dword ptr [__security_cookie] (3b 0d rel32)
    //   jne +2 ; ret
    s(
        "__security_check_cookie",
        10,
        &[0x3b, 0x0d, 0, 0, 0, 0, 0x75, 0x02, 0xc3],
    ),
    // ── x64: _chkstk, the MSVC stack-probe helper ────────────────────────
    //   cmp rax, 0x1000      (48 3d 00 10 00 00)
    //   jbe short +0x10      (76 10)
    //   lea rcx, [rsp+10h]   (48 8d 4c 24 10)
    s(
        "_chkstk",
        16,
        &[
            0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x76, 0x10, 0x48, 0x8d, 0x4c, 0x24, 0x10, 0x00,
            0x00, 0x00, 0x00,
        ],
    ),
    // compiler-rt x64: __stack_chk_fail, the famous "call yourself then fix
    // up the return address" trick:
    //   push rax; call <self>; pop rax; add rax,5; push rax; ret
    s(
        "__stack_chk_fail",
        13,
        &[
            0x50, 0xe8, 0, 0, 0, 0, 0x58, 0x48, 0x83, 0xc0, 0x05, 0x50, 0xc3,
        ],
    ),
    // compiler-rt ARM64: __stack_chk_fail
    //   stp x29, x30, [sp, #-16]!   (fd 7b bf a9)
    //   bl <self>                   (94 rel28)
    s(
        "__stack_chk_fail",
        8,
        &[0xfd, 0x7b, 0xbf, 0xa9, 0x94, 0, 0, 0],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_x64_cookie_check() {
        // the canonical MSVC cookie check with a real displacement
        let body = [
            0x48, 0x8b, 0x05, 0x12, 0x34, 0x56, 0x78, 0x48, 0x3b, 0x04, 0x24, 0x75, 0x02, 0xf3,
            0xc3, 0xcc, 0xcc,
        ];
        assert_eq!(
            identify(&body, 0, body.len()),
            Some("__security_check_cookie")
        );
    }

    #[test]
    fn displacement_bytes_may_differ() {
        let body = [
            0x48, 0x8b, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x48, 0x3b, 0x04, 0x24, 0x75, 0x02, 0xf3,
            0xc3,
        ];
        assert_eq!(
            identify(&body, 0, body.len()),
            Some("__security_check_cookie")
        );
    }

    #[test]
    fn a_different_function_does_not_match() {
        let body = [0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20];
        assert!(identify(&body, 0, body.len()).is_none());
    }

    #[test]
    fn the_cookie_check_signature_is_at_least_distinctive_against_rain() {
        // all-zero noise must not match any pattern
        let noise = [0u8; 64];
        assert!(identify(&noise, 1, 63).is_none());
        assert!(identify(&noise, 0, 64).is_none());
    }

    #[test]
    fn too_small_does_not_match() {
        let body = [0x50, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x58];
        assert!(identify(&body, 0, body.len()).is_none());
    }

    #[test]
    fn matches_the_arm64_or_chkstk() {
        let chkstk = [
            0x48, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x76, 0x10, 0x48, 0x8d, 0x4c, 0x24, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x5a, 0x48, 0x2b, 0xd1,
        ];
        assert_eq!(identify(&chkstk, 0, chkstk.len()), Some("_chkstk"));

        let arm = [0xfd, 0x7b, 0xbf, 0xa9, 0x94, 0xaa, 0xaa, 0xaa];
        assert_eq!(identify(&arm, 0, arm.len()), Some("__stack_chk_fail"));
    }
}
