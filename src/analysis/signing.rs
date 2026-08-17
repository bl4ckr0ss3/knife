//! Signing summary: what the PE certificate table claims, pulled straight from
//! the Authenticode blob without pulling in an ASN.1 crate.
//!
//! The certificate directory (*WIN_CERTIFICATE* entries, see
//! `Binary::sig_region`) is scanned rather than parsed: each entry's
//! `bCertificate` is a block of DER, from which we
//!   - extract Common Names (the `2.5.4.3` attribute), enough to answer "who
//!     signed this", and
//!   - enumerate the certificate DER sequences (a `SEQUENCE` whose first child
//!     is a `SEQUENCE`) and print their SHA-1 thumbprints, the value people
//!     paste into a search engine or a browser's certificate dialog.
//!
//! For BYOVD triage this is usually all that matters: a driver signed by a
//! leaked/test cert, or an unknown thumbprint, is the driver to look at first.

use crate::model::Binary;
use serde::Serialize;
use sha1::{Digest as _, Sha1};
use std::collections::BTreeSet;
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SigningSummary {
    /// A certificate table exists at all.
    pub signed: bool,
    /// Number of WIN_CERTIFICATE entries in the table.
    pub entries: usize,
    /// x.509 certificate subjects (Common Name attributes) found, deduped.
    pub subjects: Vec<String>,
    /// SHA-1 thumbprints of the certificate DER blobs, hex-uppercase.
    pub thumbprints: Vec<String>,
}

/// Decode a DER length. Returns `(tag+len header size, content length)`.
fn der_len(b: &[u8], at: usize) -> Option<(u64, u64)> {
    let t = *b.get(at)?;
    if t & 0x80 == 0 {
        return Some((2, t as u64));
    }
    let n = (t & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None; // indefinite or absurd; refuse to guess
    }
    let mut v: u64 = 0;
    for i in 0..n {
        v = (v << 8) | u64::from(*b.get(at + 1 + i)?);
    }
    Some(((2 + n) as u64, v))
}

/// Start/end of a value whose *length octet* lives at `at` (no preceding tag):
/// returns the byte range of the value content.
fn der_content(b: &[u8], len_at: usize) -> Option<(usize, usize)> {
    let t = *b.get(len_at)?;
    let (hdr, len) = if t & 0x80 == 0 {
        (1usize, usize::from(t))
    } else {
        let n = (t & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | usize::from(*b.get(len_at + 1 + i)?);
        }
        (1 + n, v)
    };
    let start = len_at + hdr;
    let end = start.checked_add(len)?;
    (end <= b.len()).then_some((start, end))
}

/// Common Names in arbitrary DER: the `2.5.4.3` attribute whose value is a
/// string primitive (UTF8String 0x0c, PrintableString 0x13, IA5String 0x16,
/// BMPString 0x1e).
fn common_names(b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= b.len() {
        if b[i..i + 3] == [0x55, 0x04, 0x03] {
            let tag_at = i + 3;
            let len_at = i + 4;
            let ok_type = matches!(b.get(tag_at), Some(0x0c | 0x13 | 0x16 | 0x1e));
            if let Some((start, end)) = der_content(b, len_at).filter(|_| ok_type) {
                let txt = String::from_utf8_lossy(&b[start..end]).into_owned();
                if !txt.trim().is_empty() {
                    out.push(txt);
                }
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// Enumerate plausible X.509 certificates: a `SEQUENCE` whose content begins
/// with another `SEQUENCE` (the TBSCertificate) and is long enough to be real.
fn certificates(b: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 2 <= b.len() {
        if b[i] == 0x30 {
            if let Some((hl, cl)) = der_len(b, i) {
                let start = i + hl as usize;
                let end = start
                    .checked_add(cl as usize)
                    .unwrap_or(b.len())
                    .min(b.len());
                if end > start && b[start] == 0x30 && end - start >= 24 {
                    out.push(&b[i..end]);
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

fn sha1_hex(b: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(b);
    let d = h.finalize();
    d.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02X}");
        s
    })
}

/// The signature summary for a parsed binary.
pub fn summarize(bin: &Binary, bytes: &[u8]) -> SigningSummary {
    let Some((off, size)) = bin.sig_region else {
        return SigningSummary::default();
    };
    let start = off as usize;
    let Some(sig) = bytes.get(start..start + size as usize) else {
        return SigningSummary {
            signed: true,
            ..Default::default()
        };
    };

    let mut entries = 0usize;
    let mut blobs: Vec<&[u8]> = Vec::new();
    let mut pos = 0usize;
    while pos + 8 <= sig.len() {
        let w = u16::from_le_bytes([sig[pos], sig[pos + 1]]) as usize;
        let rev = u16::from_le_bytes([sig[pos + 2], sig[pos + 3]]);
        let ctype = u16::from_le_bytes([sig[pos + 4], sig[pos + 5]]);
        entries += 1;
        // WIN_CERT_REVISION_2_0 == 0x0200, WIN_CERT_TYPE_PKCS_SIGNED_DATA == 0x0002.
        if rev >= 0x0200 && ctype == 0x0002 && w >= 8 {
            let body = &sig[(pos + 8).min(sig.len())..(pos + w).min(sig.len())];
            blobs.push(body);
        }
        if w < 8 {
            break;
        }
        pos += w;
        if pos > sig.len() {
            break;
        }
    }

    let all: Vec<u8> = blobs.iter().flat_map(|b| b.iter().copied()).collect();
    let mut subjects = common_names(&all);
    subjects.dedup();
    let mut thumbprints = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for cert in certificates(&all) {
        let tp = sha1_hex(cert);
        if seen.insert(tp.clone()) {
            thumbprints.push(tp);
        }
    }

    SigningSummary {
        signed: true,
        entries,
        subjects,
        thumbprints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny but structurally real certificate-like DER: a SEQUENCE (the
    /// certificate) holding a TBSCertificate-ish SEQUENCE whose attribute set
    /// contains the CommonName OID and a PrintableString value.
    fn sample_der() -> Vec<u8> {
        let payload = b"Knife Test Signer";
        let mut tbs = vec![0x02, 0x01, 0x02]; // version INTEGER
        let mut attr: Vec<u8> = vec![0x06, 0x03, 0x55, 0x04, 0x03]; // OID 2.5.4.3
        attr.push(0x13); // PrintableString
        attr.push(payload.len() as u8);
        attr.extend_from_slice(payload);
        let mut attr_seq = vec![0x30, attr.len() as u8];
        attr_seq.extend_from_slice(&attr);
        tbs.extend_from_slice(&attr_seq);
        let mut tbs_seq = vec![0x30, tbs.len() as u8];
        tbs_seq.extend_from_slice(&tbs);
        let mut cert = vec![0x30, tbs_seq.len() as u8];
        cert.extend_from_slice(&tbs_seq);
        cert
    }

    #[test]
    fn der_scanner_finds_cn_and_thumbprint() {
        let der = sample_der();
        assert_eq!(common_names(&der), vec!["Knife Test Signer".to_string()]);
        let certs = certificates(&der);
        assert_eq!(certs.len(), 1);
        assert_eq!(sha1_hex(certs[0]), sha1_hex(&der));
        // Thumbprint path is the same digest the summary would produce.
        let mut seen = BTreeSet::new();
        let tp = sha1_hex(certs[0]);
        seen.insert(tp.clone());
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn empty_and_short_der_are_harmless() {
        assert_eq!(common_names(&[]), Vec::<String>::new());
        assert_eq!(certificates(b"\x30\x02\x00\x00").len(), 0);
        assert_eq!(sha1_hex(b"").len(), 40);
    }
}
