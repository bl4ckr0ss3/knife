//! Constant / artifact scanning: find the fingerprints of crypto primitives,
//! packers, and embedded formats by their known byte sequences. This is how you
//! tell, statically, that a stripped blob is "doing AES" or "has a zip inside".

use crate::model::Binary;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub name: String,
    pub category: String, // crypto | hash | encoding | packer | embedded
    pub offset: u64,
    pub section: Option<String>,
    pub note: String,
}

/// Scan the whole file for every known signature.
pub fn scan(bin: &Binary, bytes: &[u8]) -> Vec<Hit> {
    let mut hits = Vec::new();

    for sig in fixed_signatures() {
        // find every occurrence, not just the first
        let mut base = 0usize;
        while let Some(pos) = find(&bytes[base..], &sig.needle) {
            let off = (base + pos) as u64;
            hits.push(Hit {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                offset: off,
                section: section_at(bin, off),
                note: sig.note.to_string(),
            });
            base += pos + 1;
            if hits.len() > 4096 {
                break;
            }
        }
    }

    // Embedded PE at a non-zero offset (dropped/bundled payload). "MZ" alone is
    // two common bytes, so validate the DOS→PE header chain: e_lfanew must point
    // at a "PE\0\0" signature inside the file.
    let mut base = 1usize;
    while let Some(pos) = find(&bytes[base..], b"MZ") {
        let off = base + pos;
        if is_pe_at(bytes, off) {
            hits.push(Hit {
                name: "embedded PE".into(),
                category: "embedded".into(),
                offset: off as u64,
                section: section_at(bin, off as u64),
                note: "bundled or dropped PE image".into(),
            });
        }
        base = off + 2;
        if base >= bytes.len() {
            break;
        }
    }

    hits.sort_by_key(|h| h.offset);
    hits
}

/// True if a valid-looking PE begins at `off`: MZ magic, an in-bounds
/// e_lfanew, and a "PE\0\0" signature there.
fn is_pe_at(bytes: &[u8], off: usize) -> bool {
    if off + 0x40 > bytes.len() || &bytes[off..off + 2] != b"MZ" {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([
        bytes[off + 0x3c],
        bytes[off + 0x3d],
        bytes[off + 0x3e],
        bytes[off + 0x3f],
    ]) as usize;
    let pe = off + e_lfanew;
    // reject absurd offsets and require the PE signature to actually be there
    (0x40..0x1000).contains(&e_lfanew) && pe + 4 <= bytes.len() && &bytes[pe..pe + 4] == b"PE\0\0"
}

fn section_at(bin: &Binary, off: u64) -> Option<String> {
    bin.sections
        .iter()
        .find(|s| s.file_size > 0 && off >= s.file_off && off < s.file_off + s.file_size)
        .map(|s| s.name.clone())
}

struct Sig {
    name: &'static str,
    category: &'static str,
    note: &'static str,
    needle: Vec<u8>,
}

fn fixed_signatures() -> &'static [Sig] {
    static S: OnceLock<Vec<Sig>> = OnceLock::new();
    S.get_or_init(|| {
        let mut v: Vec<Sig> = Vec::new();

        // ── AES ──────────────────────────────────────────────────────────
        v.push(Sig {
            name: "AES S-box",
            category: "crypto",
            note: "AES / Rijndael substitution table",
            needle: aes_sbox().to_vec(),
        });
        v.push(Sig {
            name: "AES inverse S-box",
            category: "crypto",
            note: "AES decryption table",
            needle: aes_inv_sbox().to_vec(),
        });
        v.push(Sig {
            name: "AES Te0 / T-table",
            category: "crypto",
            note: "AES round T-table (first entries)",
            needle: vec![0xc6, 0x63, 0x63, 0xa5, 0xf8, 0x7c, 0x7c, 0x84],
        });

        // ── hash init/round constants (both byte orders) ─────────────────
        push_words(
            &mut v,
            "SHA-256 init",
            "hash",
            "H0..H7 initial hash values",
            &[
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
        );
        push_words(
            &mut v,
            "SHA-256 K",
            "hash",
            "round constants (first 8)",
            &[
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5,
            ],
        );
        push_words(
            &mut v,
            "SHA-1 init",
            "hash",
            "H0..H4 initial hash values",
            &[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
        );
        // MD5 init is the SHA-1 first four; require the MD5 sine table start to disambiguate.
        push_words(
            &mut v,
            "MD5 T-table",
            "hash",
            "sin() round constants (first 4)",
            &[0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee],
        );
        // CRC32 (reversed poly 0xEDB88320) table, first 4 entries.
        push_words_le(
            &mut v,
            "CRC32 table",
            "hash",
            "IEEE 802.3 CRC table (reversed poly)",
            &[0x00000000, 0x77073096, 0xee0e612c, 0x990951ba],
        );

        // ── encodings ────────────────────────────────────────────────────
        v.push(Sig {
            name: "Base64 alphabet",
            category: "encoding",
            note: "standard Base64 charset",
            needle: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec(),
        });
        v.push(Sig {
            name: "Base64 URL-safe alphabet",
            category: "encoding",
            note: "URL-safe Base64 charset",
            needle: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".to_vec(),
        });

        // ── packers / archives / compressed blobs ────────────────────────
        v.push(sig("UPX!", "packer", "UPX packer marker", b"UPX!"));
        v.push(sig("MPRESS", "packer", "MPRESS packer marker", b"MPRESS1"));
        v.push(sig(
            ".NET metadata (BSJB)",
            "embedded",
            "CLR metadata header",
            b"BSJB",
        ));
        v.push(sig(
            "PK zip",
            "embedded",
            "ZIP / JAR / APK / OOXML",
            b"PK\x03\x04",
        ));
        v.push(sig(
            "7-Zip",
            "embedded",
            "7z archive",
            b"7z\xbc\xaf\x27\x1c",
        ));
        v.push(sig("gzip", "embedded", "gzip stream", b"\x1f\x8b\x08"));
        // zlib's 2-byte header (0x78 0x9c/0xda) is too common to report raw; it
        // would fire on coincidental bytes throughout any binary. Skipped.
        v.push(sig("PNG", "embedded", "PNG image", b"\x89PNG\r\n\x1a\n"));
        v.push(sig("PDF", "embedded", "PDF document", b"%PDF-"));

        v
    })
}

fn sig(name: &'static str, category: &'static str, note: &'static str, needle: &[u8]) -> Sig {
    Sig {
        name,
        category,
        note,
        needle: needle.to_vec(),
    }
}

/// Push a signature searchable in both big- and little-endian word order, since
/// constants appear one way in specs and the other way in compiled tables.
fn push_words(
    v: &mut Vec<Sig>,
    name: &'static str,
    cat: &'static str,
    note: &'static str,
    words: &[u32],
) {
    let be: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
    let le: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.push(Sig {
        name,
        category: cat,
        note,
        needle: be,
    });
    v.push(Sig {
        name,
        category: cat,
        note,
        needle: le,
    });
}

/// Little-endian only (e.g. lookup tables that are already stored LE).
fn push_words_le(
    v: &mut Vec<Sig>,
    name: &'static str,
    cat: &'static str,
    note: &'static str,
    words: &[u32],
) {
    let le: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    v.push(Sig {
        name,
        category: cat,
        note,
        needle: le,
    });
}

/// Naive substring search. Needles are short or rare, files are small; this is
/// plenty fast and has no dependencies.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ── AES S-box, generated rather than hard-coded as 256 literals ───────────

fn aes_sbox() -> &'static [u8; 256] {
    static SBOX: OnceLock<[u8; 256]> = OnceLock::new();
    SBOX.get_or_init(|| {
        let mut sbox = [0u8; 256];
        let mut p: u8 = 1;
        let mut q: u8 = 1;
        loop {
            // p *= 3 in GF(2^8)
            p = p ^ (p << 1) ^ if p & 0x80 != 0 { 0x1b } else { 0 };
            // q /= 3 (three multiplications by the inverse of 3)
            q ^= q << 1;
            q ^= q << 2;
            q ^= q << 4;
            if q & 0x80 != 0 {
                q ^= 0x09;
            }
            let xformed =
                q ^ q.rotate_left(1) ^ q.rotate_left(2) ^ q.rotate_left(3) ^ q.rotate_left(4);
            sbox[p as usize] = xformed ^ 0x63;
            if p == 1 {
                break;
            }
        }
        sbox[0] = 0x63;
        sbox
    })
}

fn aes_inv_sbox() -> &'static [u8; 256] {
    static INV: OnceLock<[u8; 256]> = OnceLock::new();
    INV.get_or_init(|| {
        let sbox = aes_sbox();
        let mut inv = [0u8; 256];
        for (i, &s) in sbox.iter().enumerate() {
            inv[s as usize] = i as u8;
        }
        inv
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_sbox_is_correct() {
        let s = aes_sbox();
        // known anchors from the AES spec
        assert_eq!(s[0x00], 0x63);
        assert_eq!(s[0x01], 0x7c);
        assert_eq!(s[0x53], 0xed);
        assert_eq!(s[0xff], 0x16);
    }

    #[test]
    fn inv_sbox_inverts() {
        let s = aes_sbox();
        let inv = aes_inv_sbox();
        for i in 0..=255u8 {
            assert_eq!(inv[s[i as usize] as usize], i);
        }
    }

    #[test]
    fn finds_base64_and_sbox() {
        let bin =
            crate::model::Binary::stub(crate::model::Format::Unknown, crate::model::Arch::Other);
        let mut data = vec![0u8; 32];
        data.extend_from_slice(aes_sbox());
        data.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        let hits = scan(&bin, &data);
        assert!(hits.iter().any(|h| h.name == "AES S-box"));
        assert!(hits.iter().any(|h| h.name == "Base64 alphabet"));
    }
}
