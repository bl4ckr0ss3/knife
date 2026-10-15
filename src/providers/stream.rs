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
}
