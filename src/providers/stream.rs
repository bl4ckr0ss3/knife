//! Streaming response assembly for the model transports.
//!
//! Hosted OpenAI-compatible endpoints answer `stream: true` requests with
//! Server-Sent Events; Ollama answers with newline-delimited JSON. Both arrive
//! incrementally while Knife shows progress, and both must reassemble into
//! exactly the same assistant-message shape the non-streaming transports
//! return, so the conversation loop stays transport-neutral.

use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Which protocol a streamed body speaks.
#[derive(Clone, Copy)]
pub(crate) enum StreamKind {
    OpenAiSse,
    OllamaNdjson,
}

/// Incremental progress extractor for streamed model replies.
///
/// Feeds raw transport chunks, splits complete lines at byte level (safe
/// across chunked UTF-8 boundaries), and reports a live tail of the model's
/// visible text — and its reasoning when the provider streams one — so the
/// analyst watches the thought process instead of a silent spinner. Reports
/// are throttled so tiny deltas cannot flood the activity line.
pub(crate) struct StreamTailer {
    kind: StreamKind,
    pending: Vec<u8>,
    content: String,
    reasoning: String,
    content_chars: usize,
    reasoning_chars: usize,
    reported_at: usize,
    last_tool: String,
}

impl StreamTailer {
    pub(crate) fn new(kind: StreamKind) -> Self {
        Self {
            kind,
            pending: Vec::new(),
            content: String::new(),
            reasoning: String::new(),
            content_chars: 0,
            reasoning_chars: 0,
            reported_at: 0,
            last_tool: String::new(),
        }
    }

    pub(crate) fn feed(&mut self, chunk: &[u8], report: &mut dyn FnMut(&str)) {
        self.pending.extend_from_slice(chunk);
        while let Some(position) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=position).collect();
            self.process_line(&line[..line.len() - 1], report);
        }
        if self.pending.len() > 64 * 1024 {
            // A pathological unterminated line must not grow without bound;
            // drop it and keep streaming the rest of the body.
            self.pending.clear();
        }
    }

    /// Closing status line once the stream ends.
    pub(crate) fn summary(&self) -> String {
        if self.content_chars > 0 {
            format!("Reply complete: {} chars", self.content_chars)
        } else if self.reasoning_chars > 0 {
            format!("Thinking complete: {} chars", self.reasoning_chars)
        } else {
            "Stream ended without visible reply text".to_string()
        }
    }

    fn process_line(&mut self, line: &[u8], report: &mut dyn FnMut(&str)) {
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end_matches('\r');
        let payload = match self.kind {
            StreamKind::OpenAiSse => {
                let Some(data) = text.trim().strip_prefix("data:") else {
                    return;
                };
                let data = data.trim();
                if data.is_empty() || data == "[DONE]" {
                    return;
                }
                data
            }
            StreamKind::OllamaNdjson => {
                let trimmed = text.trim();
                if trimmed.is_empty() {
                    return;
                }
                trimmed
            }
        };
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let (content_delta, reasoning_delta, tool_name) = match self.kind {
            StreamKind::OpenAiSse => {
                let Some(delta) = value.pointer("/choices/0/delta") else {
                    return;
                };
                (
                    delta.get("content").and_then(Value::as_str),
                    delta
                        .get("reasoning_content")
                        .or_else(|| delta.get("reasoning"))
                        .and_then(Value::as_str),
                    delta
                        .pointer("/tool_calls/0/function/name")
                        .and_then(Value::as_str),
                )
            }
            StreamKind::OllamaNdjson => {
                let Some(message) = value.get("message") else {
                    return;
                };
                (
                    message.get("content").and_then(Value::as_str),
                    None,
                    message
                        .pointer("/tool_calls/0/function/name")
                        .and_then(Value::as_str),
                )
            }
        };
        if let Some(piece) = reasoning_delta {
            self.reasoning.push_str(piece);
            self.reasoning_chars += piece.chars().count();
        }
        if let Some(piece) = content_delta {
            self.content.push_str(piece);
            self.content_chars += piece.chars().count();
        }
        if let Some(name) = tool_name {
            if !name.is_empty() && self.last_tool != name {
                self.last_tool = name.to_string();
                report(&format!("Preparing tool call: {name}"));
                self.reported_at = self.content_chars + self.reasoning_chars;
                return;
            }
        }
        let total = self.content_chars + self.reasoning_chars;
        if total.saturating_sub(self.reported_at) >= 120 {
            self.reported_at = total;
            if self.content_chars > 0 {
                report(&format!(
                    "Replying… {} chars · {}",
                    self.content_chars,
                    tail(&self.content)
                ));
            } else {
                report(&format!(
                    "Thinking… {} chars · {}",
                    self.reasoning_chars,
                    tail(&self.reasoning)
                ));
            }
        }
    }
}

/// The last `chars` of `text` on one line, for a single-line status display.
fn tail(text: &str) -> String {
    let collected: String = text
        .chars()
        .rev()
        .take(96)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    collected.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reassemble an OpenAI-compatible SSE body into one assistant message.
///
/// Content deltas concatenate; tool calls reassemble by index from `id`,
/// `function.name`, and `function.arguments` fragments. Unparseable or
/// non-data lines are skipped, so keep-alives and provider comments cannot
/// break the stream, but a body with no parseable `data:` event is an error.
pub(crate) fn openai_sse_message(body: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(body);
    let mut content = String::new();
    // index -> (id, name, argument fragments)
    let mut calls: BTreeMap<u64, (Option<String>, String, String)> = BTreeMap::new();
    let mut parsed_any = false;
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        parsed_any = true;
        let Some(delta) = value.pointer("/choices/0/delta") else {
            continue;
        };
        if let Some(piece) = delta.get("content").and_then(Value::as_str) {
            content.push_str(piece);
        }
        if let Some(fragments) = delta.get("tool_calls").and_then(Value::as_array) {
            for fragment in fragments {
                let index = fragment
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let entry = calls.entry(index).or_default();
                if entry.0.is_none() {
                    if let Some(id) = fragment.get("id").and_then(Value::as_str) {
                        entry.0 = Some(id.to_string());
                    }
                }
                if let Some(name) = fragment.pointer("/function/name").and_then(Value::as_str) {
                    entry.1.push_str(name);
                }
                if let Some(arguments) = fragment
                    .pointer("/function/arguments")
                    .and_then(Value::as_str)
                {
                    entry.2.push_str(arguments);
                }
            }
        }
    }
    if !parsed_any {
        return Err(anyhow!("stream contained no parseable SSE data events"));
    }
    Ok(assembled_message(&content, calls_into_tool_calls(calls)))
}

/// Reassemble an Ollama ndjson stream body into one assistant message.
///
/// Ollama sends complete tool calls inside a single chunk; content deltas
/// concatenate across chunks. Blank or unparseable lines are skipped, but a
/// body with no parseable JSON line is an error.
pub(crate) fn ollama_ndjson_message(body: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(body);
    let mut content = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut parsed_any = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        parsed_any = true;
        let Some(message) = value.get("message") else {
            continue;
        };
        if let Some(piece) = message.get("content").and_then(Value::as_str) {
            content.push_str(piece);
        }
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            tool_calls.extend(calls.iter().cloned());
        }
    }
    if !parsed_any {
        return Err(anyhow!("stream contained no parseable Ollama JSON lines"));
    }
    Ok(assembled_message(&content, tool_calls))
}

fn calls_into_tool_calls(calls: BTreeMap<u64, (Option<String>, String, String)>) -> Vec<Value> {
    calls
        .into_iter()
        .map(|(index, (id, name, arguments))| {
            json!({
                "id": id.unwrap_or_else(|| format!("call_{index}")),
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            })
        })
        .collect()
}

fn assembled_message(content: &str, tool_calls: Vec<Value>) -> Value {
    let mut message = json!({"role": "assistant"});
    if !content.is_empty() {
        message["content"] = json!(content);
    }
    if !tool_calls.is_empty() {
        message["tool_calls"] = json!(tool_calls);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_content_deltas_reassemble_into_one_message() {
        let body = b": keep-alive comment\n\
             data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"Hel\"}}]}\n\
             \n\
             data: {\"choices\":[{\"delta\":{\"content\":\"lo world\"}}]}\n\n\
             data: [DONE]\n\n";
        let message = openai_sse_message(body).unwrap();
        assert_eq!(message["role"], "assistant");
        assert_eq!(message["content"], "Hello world");
        assert!(message.get("tool_calls").is_none());
    }

    #[test]
    fn sse_tool_call_fragments_reassemble_by_index() {
        let body = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"strings\",\"arguments\":\"{\\\"qu\"}}]}}]}\n\n\
             data: {\"choices\":[{\"delta\":{\"content\":\"checking\"}}]}\n\n\
             data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ery\\\":\\\"flag\\\"}\"}}]}}]}\n\n\
             data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_2\",\"function\":{\"name\":\"info\",\"arguments\":\"{}\"}}]}}]}\n\n\
             data: [DONE]\n\n";
        let message = openai_sse_message(body).unwrap();
        assert_eq!(message["content"], "checking");
        let calls = message["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_9");
        assert_eq!(calls[0]["function"]["name"], "strings");
        assert_eq!(calls[0]["function"]["arguments"], r#"{"query":"flag"}"#);
        assert_eq!(calls[1]["id"], "call_2");
    }

    #[test]
    fn a_missing_tool_call_id_is_generated_not_dropped() {
        let body = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"session_status\",\"arguments\":\"{}\"}}]}}]}\n\n";
        let message = openai_sse_message(body).unwrap();
        assert_eq!(message["tool_calls"][0]["id"], "call_0");
        assert_eq!(
            message["tool_calls"][0]["function"]["name"],
            "session_status"
        );
    }

    #[test]
    fn a_body_without_data_events_is_an_error() {
        assert!(openai_sse_message(b": only comments\n\n").is_err());
        assert!(openai_sse_message(b"").is_err());
    }

    #[test]
    fn ollama_ndjson_deltas_reassemble_with_complete_tool_calls() {
        let body = b"{\"message\":{\"role\":\"assistant\",\"content\":\"Hel\"},\"done\":false}\n\
             {\"message\":{\"role\":\"assistant\",\"content\":\"lo\"},\"done\":false}\n\
             {\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"strings\",\"arguments\":{\"query\":\"flag\"}}}]},\"done\":true}\n";
        let message = ollama_ndjson_message(body).unwrap();
        assert_eq!(message["content"], "Hello");
        let calls = message["tool_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["function"]["name"], "strings");
        assert_eq!(calls[0]["function"]["arguments"]["query"], "flag");
    }

    #[test]
    fn an_ollama_body_without_json_lines_is_an_error() {
        assert!(ollama_ndjson_message(b"not json\n").is_err());
        assert!(ollama_ndjson_message(b"").is_err());
    }

    #[test]
    fn the_tailer_streams_thought_then_reply_with_throttled_reports() {
        let mut tailer = StreamTailer::new(StreamKind::OpenAiSse);
        let mut reports: Vec<String> = Vec::new();
        // Reasoning first. The value is split across three chunks, including
        // the two bytes of é, so a chunk boundary must not corrupt the line.
        let ones = "w".repeat(100);
        let fifties = "w".repeat(50);
        tailer.feed(
            format!("data: {{\"choices\":[{{\"delta\":{{\"reasoning_content\":\"{ones}").as_bytes(),
            &mut |m| reports.push(m.to_string()),
        );
        tailer.feed(fifties.as_bytes(), &mut |m| reports.push(m.to_string()));
        tailer.feed(&[0xC3], &mut |m| reports.push(m.to_string()));
        tailer.feed(b"\xA9tre\"}}]}\n\n", &mut |m| reports.push(m.to_string()));
        assert!(
            reports.iter().any(|m| m.starts_with("Thinking…")),
            "{reports:?}"
        );
        tailer.feed(
            format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
                "Reading the gate constants. ".repeat(6)
            )
            .as_bytes(),
            &mut |m| reports.push(m.to_string()),
        );
        assert!(
            reports.iter().any(|m| m.starts_with("Replying…")),
            "{reports:?}"
        );
        assert!(tailer.summary().starts_with("Reply complete: "));
    }

    #[test]
    fn the_tailer_announces_tool_calls_and_ignores_keepalives() {
        let mut tailer = StreamTailer::new(StreamKind::OpenAiSse);
        let mut reports = Vec::new();
        tailer.feed(b": ping\n\ndata: [DONE]\n\n", &mut |m| {
            reports.push(m.to_string())
        });
        assert!(reports.is_empty(), "{reports:?}");
        tailer.feed(
            b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"strings\"}}]}}]}\n\n",
            &mut |m| reports.push(m.to_string()),
        );
        assert_eq!(
            reports.last().map(String::as_str),
            Some("Preparing tool call: strings")
        );
        // Repeating the same name must not re-announce.
        tailer.feed(
            b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n",
            &mut |m| reports.push(m.to_string()),
        );
        assert_eq!(
            reports.last().map(String::as_str),
            Some("Preparing tool call: strings")
        );
    }

    #[test]
    fn the_tailer_handles_ollama_lines_and_bounded_pending() {
        let mut tailer = StreamTailer::new(StreamKind::OllamaNdjson);
        let mut reports = Vec::new();
        tailer.feed(
            b"{\"message\":{\"content\":\"Hello world\"},\"done\":false}\n",
            &mut |m| reports.push(m.to_string()),
        );
        // An unterminated monster line is dropped, not grown without bound.
        tailer.feed(&[b'x'; 70 * 1024], &mut |m| reports.push(m.to_string()));
        assert!(tailer.summary().starts_with("Reply complete: "));
    }
}
