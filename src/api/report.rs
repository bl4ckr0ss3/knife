//! Deterministic shareable investigation reports.
//!
//! The builder renders the saved investigation ledger as a Markdown report the
//! analyst can review, archive, or publish. Output depends only on the ledger
//! contents and the supplied target identity: no clock, no locale, no provider
//! state. Every front end that calls this observes the same bytes.

use crate::api::evidence::{EvidenceKind, EvidenceLocation};
use crate::api::investigation::{Investigation, Role};

/// Per-message character bound. The desk already stores messages within this
/// bound; the report never grows one beyond what the ledger saved and marks
/// any further truncation explicitly.
const MAX_MESSAGE_CHARS: usize = 7000;
/// Evidence inventory bound with an explicit truncation marker.
const MAX_EVIDENCE_RECORDS: usize = 24;
/// Per-record summary bound so one verbose record cannot dominate the file.
const MAX_SUMMARY_CHARS: usize = 300;
/// Shareable-recap extraction bound; a tweet-length recap never needs more.
const MAX_RECAP_CHARS: usize = 600;

/// Presentation-neutral identity of the analyzed artifact.
pub struct ReportTarget<'a> {
    pub name: &'a str,
    pub format: &'a str,
    pub architecture: &'a str,
    pub sha256: &'a str,
}

/// Render the ledger as a shareable Markdown report.
pub fn markdown(target: &ReportTarget, ledger: &Investigation) -> String {
    let mut report = String::new();
    report.push_str("# Knife investigation report — ");
    report.push_str(target.name);
    report.push_str("\n\n");
    report.push_str(&format!(
        "- Target: {} ({}, {})\n- SHA-256: `{}`\n",
        target.name, target.format, target.architecture, target.sha256
    ));
    if let Some(recap) = shareable_recap(ledger) {
        report.push_str("\n## Shareable recap\n\n");
        report.push_str(&recap);
        report.push('\n');
    }
    report.push_str("\n## Conversation\n");
    let mut conversation = false;
    for message in &ledger.messages {
        if message.role == Role::Tool {
            // Tool transcripts are protocol detail, not report prose.
            continue;
        }
        conversation = true;
        let speaker = match message.role {
            Role::Analyst => "Analyst",
            Role::Assistant => "Knife",
            Role::Tool => unreachable!("tool messages are filtered above"),
        };
        report.push_str(&format!("\n### {speaker}\n\n"));
        report.push_str(&bounded(&message.text, MAX_MESSAGE_CHARS));
        report.push('\n');
    }
    if !conversation {
        report.push_str("\nNo analyst conversation is saved yet.\n");
    }
    report.push_str("\n## Evidence inventory\n");
    let total = ledger.evidence.len();
    if total == 0 {
        report.push_str("\nNo evidence records are saved yet.\n");
    }
    for (index, (id, record)) in ledger.evidence.iter().enumerate() {
        if index == MAX_EVIDENCE_RECORDS {
            report.push_str(&format!(
                "\nShowing the first {MAX_EVIDENCE_RECORDS} of {total} evidence records; \
open the investigation desk for the rest.\n"
            ));
            break;
        }
        let summary = bounded(&one_line(&record.summary), MAX_SUMMARY_CHARS);
        let location = record
            .locations
            .iter()
            .find_map(location_label)
            .unwrap_or_else(|| "no typed location".to_string());
        report.push_str(&format!(
            "\n- `{id}` ({} via {}): {summary}\n  - Location: {location}\n",
            kind_label(record.kind),
            record.producer
        ));
        if !record.limitations.is_empty() {
            report.push_str(&format!(
                "  - Limitations: {}\n",
                one_line(&record.limitations.join("; "))
            ));
        }
    }
    report
}

/// Extract the latest `## Shareable recap` section from the newest assistant
/// answer, stopping at the next section header. Returns `None` when the model
/// did not produce one, which also covers partial budget-limited answers.
fn shareable_recap(ledger: &Investigation) -> Option<String> {
    let answer = ledger
        .messages
        .iter()
        .rev()
        .find(|message| message.role == Role::Assistant)?;
    let mut lines = answer
        .text
        .lines()
        .skip_while(|line| !is_recap_header(line))
        .peekable();
    lines.peek()?;
    lines.next();
    let mut recap = String::new();
    for line in lines {
        if line.trim_start().starts_with("## ") {
            break;
        }
        recap.push_str(line.trim_end());
        recap.push('\n');
    }
    let recap = recap.trim();
    if recap.is_empty() {
        return None;
    }
    Some(bounded(recap, MAX_RECAP_CHARS))
}

fn is_recap_header(line: &str) -> bool {
    line.trim_start()
        .to_ascii_lowercase()
        .starts_with("## shareable recap")
}

fn bounded(text: &str, limit: usize) -> String {
    let kept: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        return format!("{kept}…[truncated]");
    }
    kept
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn kind_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::TargetIdentity => "target identity",
        EvidenceKind::StaticAnalysis => "static analysis",
        EvidenceKind::RuntimeObservation => "runtime observation",
        EvidenceKind::AnalystFact => "analyst fact",
        EvidenceKind::Comparison => "comparison",
    }
}

/// Prefer the typed address an analyst can navigate to, in desk order.
fn location_label(location: &EvidenceLocation) -> Option<String> {
    if let Some(address) = location.static_address {
        return Some(format!("static VA 0x{:x}", address.get()));
    }
    if let Some(offset) = location.file_offset {
        return Some(format!("file offset 0x{:x}", offset.get()));
    }
    if let Some(address) = location.runtime_address {
        return Some(format!("runtime VA 0x{:x}", address.get()));
    }
    location
        .symbol
        .as_deref()
        .map(|symbol| format!("symbol `{symbol}`"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::StaticVa;
    use crate::api::evidence::EvidenceRecord;

    fn ledger_with_recap() -> Investigation {
        let mut ledger = Investigation::new("target-hash");
        ledger
            .append(Role::Analyst, "What is this file?".into(), vec![])
            .unwrap();
        ledger
            .append(Role::Tool, "{\"tool\":\"session_status\"}".into(), vec![])
            .unwrap();
        ledger
            .append(
                Role::Assistant,
                "## Verdict\nA benign x64 crackme.\n\n## Shareable recap\nBenign x64 \
crackme: seven validation gates feed a keyed flag decryptor; no network code."
                    .into(),
                vec![],
            )
            .unwrap();
        ledger
            .record(EvidenceRecord::new(
                "target-hash",
                "triage",
                EvidenceKind::StaticAnalysis,
                "Validator entry block observed",
                vec![EvidenceLocation {
                    static_address: Some(StaticVa(0x1400019b0)),
                    ..EvidenceLocation::default()
                }],
                vec![],
                vec![],
            ))
            .unwrap();
        ledger
    }

    #[test]
    fn report_contains_identity_conversation_and_evidence_but_not_tool_transcripts() {
        let ledger = ledger_with_recap();
        let report = markdown(
            &ReportTarget {
                name: "crackme.exe",
                format: "PE",
                architecture: "x86-64",
                sha256: "target-hash",
            },
            &ledger,
        );
        assert!(report.starts_with("# Knife investigation report — crackme.exe\n"));
        assert!(report.contains("- Target: crackme.exe (PE, x86-64)"));
        assert!(report.contains("- SHA-256: `target-hash`"));
        assert!(report.contains("### Analyst\n\nWhat is this file?"));
        assert!(report.contains("## Verdict"));
        assert!(report.contains("### Knife\n\n## Verdict"));
        assert!(!report.contains("session_status"));
        assert!(report.contains("(static analysis via triage)"));
        assert!(report.contains("static VA 0x1400019b0"));
    }

    #[test]
    fn shareable_recap_leads_and_comes_from_the_latest_answer() {
        let ledger = ledger_with_recap();
        let report = markdown(
            &ReportTarget {
                name: "crackme.exe",
                format: "PE",
                architecture: "x86-64",
                sha256: "target-hash",
            },
            &ledger,
        );
        let recap = report.find("## Shareable recap").unwrap();
        let conversation = report.find("## Conversation").unwrap();
        assert!(recap < conversation);
        assert!(report.contains("no network code."));
    }

    #[test]
    fn a_missing_recap_omits_the_section_instead_of_guessing() {
        let mut ledger = Investigation::new("target-hash");
        ledger
            .append(Role::Assistant, "Just a short note.".into(), vec![])
            .unwrap();
        let report = markdown(
            &ReportTarget {
                name: "x",
                format: "ELF",
                architecture: "aarch64",
                sha256: "target-hash",
            },
            &ledger,
        );
        assert!(!report.contains("## Shareable recap"));
        assert!(report.contains("## Conversation"));
    }

    #[test]
    fn the_evidence_inventory_is_bounded_with_an_explicit_marker() {
        let mut ledger = Investigation::new("target-hash");
        ledger
            .append(Role::Assistant, "answer".into(), vec![])
            .unwrap();
        for index in 0..30 {
            ledger
                .record(EvidenceRecord::new(
                    "target-hash",
                    "test",
                    EvidenceKind::StaticAnalysis,
                    format!("record {index}"),
                    vec![],
                    vec![],
                    vec![],
                ))
                .unwrap();
        }
        let report = markdown(
            &ReportTarget {
                name: "x",
                format: "ELF",
                architecture: "aarch64",
                sha256: "target-hash",
            },
            &ledger,
        );
        // IDs are content-derived hashes, so the deterministic inventory order
        // is the desk's own evidence order, not insertion order. Count rows.
        assert_eq!(report.matches("\n- `ev-").count(), MAX_EVIDENCE_RECORDS);
        assert!(report.contains("Showing the first 24 of 30 evidence records"));
    }

    #[test]
    fn long_text_is_bounded_and_marked_not_silently_dropped() {
        let mut ledger = Investigation::new("target-hash");
        let long = "x".repeat(MAX_SUMMARY_CHARS + 50);
        ledger
            .record(EvidenceRecord::new(
                "target-hash",
                "test",
                EvidenceKind::StaticAnalysis,
                long,
                vec![],
                vec![],
                vec![],
            ))
            .unwrap();
        let report = markdown(
            &ReportTarget {
                name: "x",
                format: "ELF",
                architecture: "aarch64",
                sha256: "target-hash",
            },
            &ledger,
        );
        assert!(report.contains("…[truncated]"));
    }
}
