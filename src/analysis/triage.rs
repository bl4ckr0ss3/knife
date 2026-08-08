//! Verdict scoring. Transparent and additive: every point is a named signal.

use super::capabilities::{self, Match};
use crate::model::{Binary, Format};
use serde::Serialize;

const PACK_THRESHOLD: f64 = 7.2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Clean,
    LowRisk,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::LowRisk => "LOW RISK",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Malicious => "MALICIOUS",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Signal {
    pub text: String,
    pub weight: i32,
    pub kind: &'static str, // info | warn | bad
}

#[derive(Serialize)]
pub struct TriageResult {
    pub score: i32,
    pub verdict: Verdict,
    pub signals: Vec<Signal>,
}

pub fn run(bin: &Binary, matches: &[Match], yara_hits: &[String]) -> TriageResult {
    let mut signals = Vec::new();
    let mut score = 0i32;
    let mut add = |text: String, weight: i32, kind: &'static str, signals: &mut Vec<Signal>| {
        signals.push(Signal { text, weight, kind });
        score += weight;
    };

    // signature (PE only carries one here)
    if bin.format == Format::Pe {
        if bin.has_signature {
            add(
                "Embedded Authenticode signature present (run a trust check to verify)".into(),
                0,
                "info",
                &mut signals,
            );
        } else {
            add("No embedded signature".into(), 1, "warn", &mut signals);
        }
    }

    // packing / entropy
    for s in bin
        .sections
        .iter()
        .filter(|s| s.entropy >= PACK_THRESHOLD && s.file_size > 0)
    {
        add(
            format!(
                "High-entropy section '{}' ({:.2}/8) — packed or encrypted",
                s.name, s.entropy
            ),
            2,
            "bad",
            &mut signals,
        );
    }
    for s in bin.sections.iter().filter(|s| s.is_wx()) {
        add(
            format!("Section '{}' is writable and executable (RWX)", s.name),
            2,
            "bad",
            &mut signals,
        );
    }
    for s in &bin.sections {
        let n = s.name.to_ascii_uppercase();
        if n.starts_with("UPX") {
            add(
                format!("UPX section name '{}'", s.name),
                2,
                "bad",
                &mut signals,
            );
            break;
        }
        if n.contains("ASPACK") || n == ".ADATA" {
            add("ASPack section name".into(), 2, "bad", &mut signals);
            break;
        }
    }

    let imported = bin.all_imported_functions().count();
    if imported > 0 && imported < 10 && bin.sections.iter().any(|s| s.entropy >= PACK_THRESHOLD) {
        add(
            format!("Only {imported} imports with packed sections — resolved at runtime"),
            2,
            "bad",
            &mut signals,
        );
    }

    // overlay
    if let Some(off) = bin.overlay_off {
        let bad = bin.overlay_entropy >= 7.2;
        let w = if bad { 2 } else { 0 };
        add(
            format!(
                "Overlay: {} past end of image ({:.2}/8) — appended data / bundle",
                crate::output::human(bin.overlay_size),
                bin.overlay_entropy
            ),
            w,
            if bad { "bad" } else { "info" },
            &mut signals,
        );
        let _ = off;
    }

    // Capability clusters. These describe attack *surface*; on their own they
    // do not prove intent (a system DLL legitimately exports injection APIs),
    // so they are weighted lower than packing/anomaly evidence and only bite
    // hard when they combine with each other.
    let caps = capabilities::cluster(matches);
    if let Some(&n) = caps.get("injection") {
        if n >= 2 {
            add(
                format!("Process-injection API cluster ({n})"),
                2,
                "warn",
                &mut signals,
            );
        }
    }
    if let Some(&n) = caps.get("anti-debug") {
        add(
            format!("Anti-debug / anti-analysis APIs ({n})"),
            1,
            "warn",
            &mut signals,
        );
    }
    if caps.contains_key("theft") {
        add(
            format!("Credential / data-theft APIs ({})", caps["theft"]),
            2,
            "bad",
            &mut signals,
        );
    }
    if caps.contains_key("surveillance") {
        add(
            format!(
                "Keylogging / screen-capture APIs ({})",
                caps["surveillance"]
            ),
            1,
            "warn",
            &mut signals,
        );
    }
    if caps.contains_key("dynamic") && caps.contains_key("evasion") {
        add(
            "Dynamic API resolution + RWX changes (unpacking pattern)".into(),
            1,
            "warn",
            &mut signals,
        );
    }
    // The strong signal is capability + concealment: injection/theft in a
    // binary that is also packed, or that reaches out over the network.
    let packed = bin.sections.iter().any(|s| s.entropy >= PACK_THRESHOLD);
    if (caps.contains_key("injection") || caps.contains_key("theft"))
        && caps.contains_key("network")
    {
        add(
            "Networking with injection/theft — remote payload or exfil".into(),
            2,
            "bad",
            &mut signals,
        );
    }
    if (caps.contains_key("injection") || caps.contains_key("theft")) && packed {
        add(
            "Injection/theft capability in a packed binary".into(),
            2,
            "bad",
            &mut signals,
        );
    }

    // A YARA match is a strong, curated signal. Weight it heavily but cap the
    // contribution so one noisy ruleset cannot alone dominate the score.
    if !yara_hits.is_empty() {
        let w = (3 * yara_hits.len() as i32).min(8);
        let names = yara_hits.join(", ");
        add(
            format!("YARA: {} rule(s) matched — {names}", yara_hits.len()),
            w,
            "bad",
            &mut signals,
        );
    }

    let total = score.max(0);
    let verdict = match total {
        0..=2 => Verdict::Clean,
        3..=5 => Verdict::LowRisk,
        6..=9 => Verdict::Suspicious,
        _ => Verdict::Malicious,
    };

    signals.sort_by_key(|s| std::cmp::Reverse(s.weight));
    TriageResult {
        score: total,
        verdict,
        signals,
    }
}
