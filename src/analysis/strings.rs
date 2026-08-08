//! Printable string extraction (ASCII + UTF-16LE) and IOC mining.

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

pub fn extract(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    ascii_run(data, min_len, &mut out);
    utf16_run(data, min_len, &mut out);
    out
}

fn ascii_run(data: &[u8], min: usize, out: &mut Vec<String>) {
    let mut cur = Vec::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            flush(&mut cur, min, out);
        }
    }
    flush(&mut cur, min, out);
}

fn utf16_run(data: &[u8], min: usize, out: &mut Vec<String>) {
    let mut cur = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let (lo, hi) = (data[i], data[i + 1]);
        if hi == 0 && (0x20..0x7f).contains(&lo) {
            cur.push(lo);
        } else {
            flush(&mut cur, min, out);
        }
        i += 2;
    }
    flush(&mut cur, min, out);
}

fn flush(cur: &mut Vec<u8>, min: usize, out: &mut Vec<String>) {
    if cur.len() >= min {
        out.push(String::from_utf8_lossy(cur).into_owned());
    }
    cur.clear();
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioc {
    pub kind: String,
    pub value: String,
}

struct Pat {
    url: Regex,
    ipv4: Regex,
    domain: Regex,
    email: Regex,
    regkey: Regex,
    winpath: Regex,
    unixpath: Regex,
    guid: Regex,
    btc: Regex,
}

fn pats() -> &'static Pat {
    static P: OnceLock<Pat> = OnceLock::new();
    P.get_or_init(|| Pat {
        url: Regex::new(r#"(?i)\bhttps?://[^\s"'<>|\\]{4,}"#).unwrap(),
        ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        domain: Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|ru|cn|top|xyz|info|biz|io|co|pw|su|onion|dev|app|club|site|online|shop|gg|me)\b").unwrap(),
        email: Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").unwrap(),
        regkey: Regex::new(r"(?i)(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\|SYSTEM\\CurrentControlSet)[\\A-Za-z0-9 _.-]{3,}").unwrap(),
        winpath: Regex::new(r#"\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\){1,}[^\\/:*?"<>|\r\n]*"#).unwrap(),
        unixpath: Regex::new(r#"(?:/(?:bin|etc|usr|var|tmp|home|opt|lib|proc|dev|root)/)[^\s\x00":]{2,}"#).unwrap(),
        guid: Regex::new(r"(?i)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?").unwrap(),
        btc: Regex::new(r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").unwrap(),
    })
}

pub fn find_iocs(strings: &[String]) -> Vec<Ioc> {
    let p = pats();
    let mut out: Vec<Ioc> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut add = |kind: &str, value: &str, out: &mut Vec<Ioc>| {
        let v = value.trim();
        if v.is_empty() {
            return;
        }
        let key = format!("{kind}|{}", v.to_ascii_lowercase());
        if seen.insert(key) {
            out.push(Ioc {
                kind: kind.to_string(),
                value: trim(v, 100),
            });
        }
    };

    for s in strings {
        for m in p.url.find_iter(s) {
            add("url", m.as_str(), &mut out);
        }
        for m in p.ipv4.find_iter(s) {
            if plausible_ip(m.as_str()) {
                add("ip", m.as_str(), &mut out);
            }
        }
        for m in p.domain.find_iter(s) {
            add("domain", m.as_str(), &mut out);
        }
        for m in p.email.find_iter(s) {
            add("email", m.as_str(), &mut out);
        }
        for m in p.btc.find_iter(s) {
            add("btc", m.as_str(), &mut out);
        }
        for m in p.regkey.find_iter(s) {
            add("regkey", m.as_str(), &mut out);
        }
        for m in p.winpath.find_iter(s) {
            add("path", m.as_str(), &mut out);
        }
        for m in p.unixpath.find_iter(s) {
            add("path", m.as_str(), &mut out);
        }
        for m in p.guid.find_iter(s) {
            add("guid", m.as_str(), &mut out);
        }
    }

    out.sort_by_key(|i| rank(&i.kind));
    out
}

fn rank(kind: &str) -> u8 {
    match kind {
        "url" => 0,
        "ip" => 1,
        "domain" => 2,
        "email" => 3,
        "btc" => 4,
        "regkey" => 5,
        "path" => 6,
        "guid" => 7,
        _ => 9,
    }
}

fn plausible_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut zeros = 0;
    let mut octs = [0u16; 4];
    for (i, p) in parts.iter().enumerate() {
        match p.parse::<u16>() {
            Ok(n) if n <= 255 => {
                octs[i] = n;
                if n == 0 {
                    zeros += 1;
                }
            }
            _ => return false,
        }
    }
    if zeros >= 2 {
        return false; // version-number lookalikes: 5.1.0.0
    }
    !(octs[0] == 0 || octs[0] == 127 || (octs[0] == 255 && octs[3] == 255))
}

fn trim(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…")
    }
}

/// Defang for safe sharing.
pub fn defang(kind: &str, v: &str) -> String {
    match kind {
        "url" => v
            .replacen("https://", "hxxps://", 1)
            .replacen("http://", "hxxp://", 1)
            .replace('.', "[.]"),
        "ip" | "domain" => match v.rfind('.') {
            Some(i) => format!("{}[.]{}", &v[..i], &v[i + 1..]),
            None => v.to_string(),
        },
        _ => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii() {
        let data = b"\x01hello world\x01".to_vec();
        let s = extract(&data, 4);
        assert!(s.iter().any(|x| x == "hello world"));
    }

    #[test]
    fn extracts_utf16() {
        // "WIDE!" as UTF-16LE at an even offset (the scanner reads aligned pairs).
        let mut data = vec![0x01u8, 0x01u8];
        data.extend_from_slice(&[b'W', 0, b'I', 0, b'D', 0, b'E', 0, b'!', 0]);
        data.push(0x01);
        let s = extract(&data, 4);
        assert!(s.iter().any(|x| x == "WIDE!"));
    }

    #[test]
    fn finds_and_defangs_iocs() {
        let s = vec![
            "connect to http://evil.example.com/gate.php now".to_string(),
            "c2 at 185.220.101.47 port 443".to_string(),
        ];
        let iocs = find_iocs(&s);
        assert!(iocs.iter().any(|i| i.kind == "url"));
        assert!(iocs
            .iter()
            .any(|i| i.kind == "ip" && i.value == "185.220.101.47"));
        assert_eq!(defang("ip", "185.220.101.47"), "185.220.101[.]47");
        assert_eq!(defang("url", "http://a.com/x"), "hxxp://a[.]com/x");
    }

    #[test]
    fn rejects_version_number_ips() {
        let s = vec!["assembly version 6.0.0.0 and 5.1.0.0".to_string()];
        let iocs = find_iocs(&s);
        assert!(!iocs.iter().any(|i| i.kind == "ip"));
    }
}
