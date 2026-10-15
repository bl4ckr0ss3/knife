//! Provider-neutral conversation loop with local and hosted transports.

use crate::api::investigation::{Investigation, Role};
use crate::workspace::Session;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::time::Duration;

const MAX_ROUNDS: usize = 8;
const MAX_CALLS: usize = 24;
const MAX_CONTEXT: usize = 512 * 1024;
const MAX_HISTORY: usize = 32 * 1024;
const MAX_HISTORY_MESSAGE: usize = 4 * 1024;
const MAX_TOOL_PREVIEW: usize = 8 * 1024;
const SYSTEM_PROMPT: &str = include_str!("agent_system_prompt.md");

#[derive(Debug, Clone)]
pub enum AgentEvent {
    Activity(String),
    ToolCompleted {
        name: String,
        static_address: Option<u64>,
    },
}

pub trait ChatProvider {
    fn complete(&mut self, messages: &[Value], tools: &[Value]) -> Result<Value>;

    fn tool_result(&self, call: &Value, name: &str, content: String) -> Result<Value> {
        let _ = call;
        Ok(json!({"role":"tool","tool_name":name,"content":content}))
    }
}

pub enum ConfiguredProvider {
    Ollama(Ollama),
    OpenAiCompatible(OpenAiCompatible),
}

#[derive(Clone)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    pub base_url: String,
}

impl AgentConfig {
    pub fn from_environment() -> Self {
        let provider = std::env::var("KNIFE_AGENT_PROVIDER").unwrap_or_else(|_| "ollama".into());
        let provider = provider.trim().to_ascii_lowercase();
        let api_key = std::env::var("KNIFE_AGENT_API_KEY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| match provider.as_str() {
                "openrouter" => std::env::var("OPENROUTER_API_KEY").ok(),
                "openai" => std::env::var("OPENAI_API_KEY").ok(),
                _ => None,
            })
            .unwrap_or_default();
        let base_url = match provider.as_str() {
            "ollama" => std::env::var("KNIFE_OLLAMA_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:11434".into()),
            "compatible" | "openai-compatible" => {
                std::env::var("KNIFE_AGENT_BASE_URL").unwrap_or_default()
            }
            _ => String::new(),
        };
        Self {
            provider,
            model: std::env::var("KNIFE_AGENT_MODEL").unwrap_or_default(),
            api_key,
            base_url,
        }
    }

    pub fn status(&self) -> String {
        match ConfiguredProvider::from_config(self) {
            Ok(provider) => format!("Ready: {}", provider.label()),
            Err(error) => format!("Offline: {error}"),
        }
    }

    pub fn has_api_key(&self) -> bool {
        !self.api_key.is_empty()
    }
}

impl ConfiguredProvider {
    pub fn from_environment() -> Result<Self> {
        Self::from_config(&AgentConfig::from_environment())
    }

    pub fn from_config(config: &AgentConfig) -> Result<Self> {
        match config.provider.trim().to_ascii_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama(Ollama::from_config(config)?)),
            "openrouter" => Ok(Self::OpenAiCompatible(
                OpenAiCompatible::from_config(OpenAiService::OpenRouter, config)?,
            )),
            "openai" => Ok(Self::OpenAiCompatible(
                OpenAiCompatible::from_config(OpenAiService::OpenAi, config)?,
            )),
            "compatible" | "openai-compatible" => Ok(Self::OpenAiCompatible(
                OpenAiCompatible::from_config(OpenAiService::Compatible, config)?,
            )),
            value => Err(anyhow!(
                "Unknown KNIFE_AGENT_PROVIDER '{value}'; use ollama, openrouter, openai, or compatible"
            )),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Ollama(provider) => format!("Ollama / {}", provider.model),
            Self::OpenAiCompatible(provider) => {
                format!("{} / {}", provider.service.label(), provider.model)
            }
        }
    }
}

impl ChatProvider for ConfiguredProvider {
    fn complete(&mut self, messages: &[Value], tools: &[Value]) -> Result<Value> {
        match self {
            Self::Ollama(provider) => provider.complete(messages, tools),
            Self::OpenAiCompatible(provider) => provider.complete(messages, tools),
        }
    }

    fn tool_result(&self, call: &Value, name: &str, content: String) -> Result<Value> {
        match self {
            Self::Ollama(provider) => provider.tool_result(call, name, content),
            Self::OpenAiCompatible(provider) => provider.tool_result(call, name, content),
        }
    }
}

pub fn provider_status() -> String {
    AgentConfig::from_environment().status()
}

pub struct Ollama {
    model: String,
    endpoint: String,
}

impl Ollama {
    pub fn from_environment() -> Result<Self> {
        Self::from_config(&AgentConfig::from_environment())
    }

    fn from_config(config: &AgentConfig) -> Result<Self> {
        let model = config.model.clone();
        if model.trim().is_empty() {
            return Err(anyhow!("choose a model with S setup"));
        }
        let endpoint = config.base_url.clone();
        // This first adapter is deliberately local. Remote authenticated
        // services will have a separate transport/configuration contract.
        let authority = endpoint
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("Ollama URL must use local HTTP"))?;
        let host = authority.split(':').next().unwrap_or("");
        if !matches!(host, "127.0.0.1" | "localhost")
            || authority.contains('/')
            || authority.contains('@')
        {
            return Err(anyhow!(
                "Ollama URL must name localhost or 127.0.0.1 with an optional port"
            ));
        }
        if model.trim().is_empty() || model.len() > 256 {
            return Err(anyhow!("invalid model name"));
        }
        Ok(Self { model, endpoint })
    }
}

impl ChatProvider for Ollama {
    fn complete(&mut self, messages: &[Value], tools: &[Value]) -> Result<Value> {
        let payload = serde_json::to_string(
            &json!({"model": self.model, "messages": messages, "tools": tools, "stream": false}),
        )?;
        if payload.len() > MAX_CONTEXT {
            return Err(anyhow!(
                "conversation exceeds the 512 KiB request budget after compaction"
            ));
        }
        let curl = crate::providers::process::find_on_path("curl")
            .ok_or_else(|| anyhow!("local model transport requires curl"))?;
        let args: Vec<OsString> = [
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--connect-timeout",
            "3",
            "--max-time",
            "60",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
        ]
        .into_iter()
        .map(OsString::from)
        .chain([
            OsString::from(payload),
            OsString::from(format!("{}/api/chat", self.endpoint)),
        ])
        .collect();
        let result = crate::providers::process::run_process(
            &curl,
            args,
            Duration::from_secs(65),
            1024 * 1024,
        )?;
        if !result.status.success() || result.truncated {
            return Err(anyhow!(
                "Ollama request failed or exceeded its output bound"
            ));
        }
        let result: Value = serde_json::from_slice(&result.stdout)?;
        let message = result
            .get("message")
            .filter(|m| m.is_object())
            .ok_or_else(|| anyhow!("model response has no assistant message"))?;
        Ok(message.clone())
    }
}

#[derive(Clone, Copy)]
enum OpenAiService {
    OpenRouter,
    OpenAi,
    Compatible,
}

impl OpenAiService {
    fn label(self) -> &'static str {
        match self {
            Self::OpenRouter => "OpenRouter",
            Self::OpenAi => "OpenAI",
            Self::Compatible => "OpenAI-compatible",
        }
    }
}

pub struct OpenAiCompatible {
    service: OpenAiService,
    model: String,
    endpoint: String,
    api_key: String,
    site_url: Option<String>,
    app_name: Option<String>,
}

impl OpenAiCompatible {
    fn from_config(service: OpenAiService, config: &AgentConfig) -> Result<Self> {
        let model = config.model.clone();
        if model.trim().is_empty() {
            return Err(anyhow!("choose a model with S setup"));
        }
        if model.len() > 256 || model.chars().any(char::is_control) {
            return Err(anyhow!("invalid KNIFE_AGENT_MODEL"));
        }
        let (endpoint, service_key) = match service {
            OpenAiService::OpenRouter => (
                "https://openrouter.ai/api/v1/chat/completions".to_string(),
                "OPENROUTER_API_KEY",
            ),
            OpenAiService::OpenAi => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "OPENAI_API_KEY",
            ),
            OpenAiService::Compatible => {
                let base = config.base_url.trim();
                if base.is_empty() {
                    return Err(anyhow!("enter a base URL with S setup"));
                }
                let base = base.trim_end_matches('/');
                let endpoint = if base.ends_with("/chat/completions") {
                    base.to_string()
                } else {
                    format!("{base}/chat/completions")
                };
                (endpoint, "KNIFE_AGENT_API_KEY")
            }
        };
        validate_remote_endpoint(&endpoint)?;
        let api_key = config.api_key.clone();
        if api_key.trim().is_empty() {
            return Err(anyhow!(
                "enter {service_key} for {} with S setup",
                service.label()
            ));
        }
        if api_key.len() > 4096 || api_key.chars().any(|ch| matches!(ch, '\r' | '\n')) {
            return Err(anyhow!("invalid API key"));
        }
        let site_url = clean_optional_header("KNIFE_OPENROUTER_SITE_URL")?;
        let app_name = clean_optional_header("KNIFE_OPENROUTER_APP_NAME")?;
        Ok(Self {
            service,
            model,
            endpoint,
            api_key,
            site_url,
            app_name,
        })
    }
}

impl ChatProvider for OpenAiCompatible {
    fn complete(&mut self, messages: &[Value], tools: &[Value]) -> Result<Value> {
        let payload = serde_json::to_vec(
            &json!({"model": self.model, "messages": messages, "tools": tools, "stream": false}),
        )?;
        if payload.len() > MAX_CONTEXT {
            return Err(anyhow!(
                "conversation exceeds the 512 KiB request budget after compaction"
            ));
        }
        let curl = crate::providers::process::find_on_path("curl")
            .ok_or_else(|| anyhow!("hosted model transport requires curl"))?;
        let headers = SecretHeaderFile::create(
            &self.api_key,
            self.site_url.as_deref(),
            self.app_name.as_deref(),
        )?;
        let args: Vec<OsString> = [
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--connect-timeout",
            "5",
            "--max-time",
            "60",
            "--header",
            "Content-Type: application/json",
            "--header",
        ]
        .into_iter()
        .map(OsString::from)
        .chain([
            OsString::from(format!("@{}", headers.path.display())),
            OsString::from("--data-binary"),
            OsString::from("@-"),
            OsString::from(&self.endpoint),
        ])
        .collect();
        let result = crate::providers::process::run_process_with_input(
            &curl,
            args,
            payload,
            Duration::from_secs(65),
            1024 * 1024,
        )?;
        if !result.status.success() || result.truncated {
            let detail: String = String::from_utf8_lossy(&result.stdout)
                .chars()
                .take(500)
                .collect();
            return Err(anyhow!(
                "{} request failed or exceeded its output bound{}",
                self.service.label(),
                if detail.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {detail}")
                }
            ));
        }
        let result: Value = serde_json::from_slice(&result.stdout)?;
        result
            .pointer("/choices/0/message")
            .filter(|message| message.is_object())
            .cloned()
            .ok_or_else(|| anyhow!("model response has no assistant message"))
    }

    fn tool_result(&self, call: &Value, _: &str, content: String) -> Result<Value> {
        let id = call
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("OpenAI-compatible tool call has no id"))?;
        Ok(json!({"role":"tool","tool_call_id":id,"content":content}))
    }
}

fn validate_remote_endpoint(endpoint: &str) -> Result<()> {
    let local_http =
        endpoint.starts_with("http://127.0.0.1:") || endpoint.starts_with("http://localhost:");
    if !endpoint.starts_with("https://") && !local_http {
        return Err(anyhow!(
            "KNIFE_AGENT_BASE_URL must use HTTPS (localhost HTTP is allowed)"
        ));
    }
    if endpoint.chars().any(char::is_control) || endpoint.contains('@') {
        return Err(anyhow!("invalid KNIFE_AGENT_BASE_URL"));
    }
    Ok(())
}

fn clean_optional_header(name: &str) -> Result<Option<String>> {
    let value = std::env::var(name).ok().filter(|value| !value.is_empty());
    if value.as_deref().is_some_and(|value| {
        value.len() > 1024 || value.chars().any(|ch| matches!(ch, '\r' | '\n'))
    }) {
        return Err(anyhow!("invalid {name}"));
    }
    Ok(value)
}

struct SecretHeaderFile {
    path: std::path::PathBuf,
}

impl SecretHeaderFile {
    fn create(api_key: &str, site_url: Option<&str>, app_name: Option<&str>) -> Result<Self> {
        use std::io::Write;
        for sequence in 0..32u8 {
            let path = std::env::temp_dir().join(format!(
                "knife-agent-headers-{}-{sequence}",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    // Construct the cleanup guard before the first secret byte
                    // is written so partial-write failures cannot leave it.
                    let secret = Self { path };
                    writeln!(file, "Authorization: Bearer {api_key}")?;
                    if let Some(value) = site_url {
                        writeln!(file, "HTTP-Referer: {value}")?;
                    }
                    if let Some(value) = app_name {
                        writeln!(file, "X-Title: {value}")?;
                    }
                    file.flush()?;
                    return Ok(secret);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(anyhow!("could not allocate agent header file"))
    }
}

impl Drop for SecretHeaderFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn converse(
    provider: &mut impl ChatProvider,
    session: &Session,
    ledger: &Investigation,
    activity: impl FnMut(&str),
) -> Result<Value> {
    converse_cancellable(
        provider,
        session,
        ledger,
        &crate::api::execution::CancellationToken::default(),
        activity,
    )
}

pub fn converse_cancellable(
    provider: &mut impl ChatProvider,
    session: &Session,
    ledger: &Investigation,
    cancellation: &crate::api::execution::CancellationToken,
    mut activity: impl FnMut(&str),
) -> Result<Value> {
    converse_with_events(provider, session, ledger, cancellation, |event| {
        if let AgentEvent::Activity(message) = event {
            activity(&message);
        }
    })
}

pub fn converse_with_events(
    provider: &mut impl ChatProvider,
    session: &Session,
    ledger: &Investigation,
    cancellation: &crate::api::execution::CancellationToken,
    mut events: impl FnMut(AgentEvent),
) -> Result<Value> {
    let expected_target = crate::analysis::hashes::sha256_hex(&session.bytes);
    let catalog = crate::tools::read_catalog();
    let mut active: std::collections::BTreeSet<String> = [
        "discover_investigation_tools",
        "session_status",
        "info",
        "triage",
        "explain_function",
        "trace_string_usage",
        "inspect_input_validation",
        "investigation_status",
        "investigation_get_evidence",
        "investigation_conflicts",
        "read_function_instructions",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let mut messages = vec![json!({"role":"system","content":SYSTEM_PROMPT})];
    let mut history = Vec::new();
    let mut history_bytes = 0usize;
    for message in ledger.messages.iter().rev() {
        // Tool transcripts are retained in the ledger for inspection, but
        // replaying them as unmatched user messages wastes context and can
        // confuse provider tool-call protocols.
        if message.role == Role::Tool {
            continue;
        }
        let text: String = message.text.chars().take(MAX_HISTORY_MESSAGE).collect();
        if history_bytes.saturating_add(text.len()) > MAX_HISTORY && !history.is_empty() {
            break;
        }
        history_bytes = history_bytes.saturating_add(text.len());
        history.push((message.role, text));
    }
    for (role, text) in history.into_iter().rev() {
        // Historical tool results are context, not unmatched protocol tool
        // responses: provider messages must have complete tool-call pairs.
        let role = if role == Role::Assistant {
            "assistant"
        } else {
            "user"
        };
        messages.push(json!({"role":role,"content":text}));
    }
    messages.insert(1,json!({"role":"system","content":"Begin with session_status. Use discover_investigation_tools to request more tools for triage, code, strings, validation, memory, or external analysis. Newly discovered tools become callable on your next model round. Consider their reported availability before calling them."}));
    let mut evidence = Vec::new();
    let mut tool_activity = Vec::new();
    let mut count = 0;
    for round in 0..MAX_ROUNDS {
        if cancellation.is_cancelled() {
            return Err(anyhow!("investigation cancelled"));
        }
        events(AgentEvent::Activity(format!(
            "Waiting for model (round {})",
            round + 1
        )));
        let schemas: Vec<_> = catalog.iter().filter(|operation|active.contains(operation.name)).map(|operation|json!({"type":"function","function":{"name":operation.name,"description":operation.description,"parameters":operation.params}})).collect();
        let response = provider.complete(&messages, &schemas)?;
        if cancellation.is_cancelled() {
            return Err(anyhow!("investigation cancelled"));
        }
        let calls = response
            .get("tool_calls")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        messages.push(response.clone());
        if calls.is_empty() {
            let answer = response
                .get("content")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow!("model returned no answer or tool calls"))?;
            return Ok(
                json!({"assistant":answer,"evidence":evidence,"tool_activity":tool_activity}),
            );
        }
        for call in calls {
            if cancellation.is_cancelled() {
                return Err(anyhow!("investigation cancelled"));
            }
            count += 1;
            if count > MAX_CALLS {
                return Err(anyhow!("agent reached the 24-tool-call limit"));
            }
            let function = &call["function"];
            let name = function["name"]
                .as_str()
                .ok_or_else(|| anyhow!("invalid tool call name"))?;
            let args = normalize_tool_arguments(&function["arguments"]);
            let result = if !active.contains(name)
                || !catalog.iter().any(|operation| operation.name == name)
                || !args.is_object()
            {
                json!({"error":"tool is unavailable or arguments are not an object"})
            } else {
                events(AgentEvent::Activity(format!("Running {name}")));
                match crate::tools::dispatch(session, name, &args) {
                    Ok(value) => value,
                    Err(error) => json!({"error": error.to_string()}),
                }
            };
            let (matching_evidence, static_address) = matching_evidence(&result, &expected_target);
            evidence.extend(matching_evidence);
            events(AgentEvent::ToolCompleted {
                name: name.into(),
                static_address,
            });
            if name == "discover_investigation_tools" {
                if let Some(tools) = result.get("tools").and_then(Value::as_array) {
                    for tool in tools {
                        if let Some(name) = tool["operation"]["name"].as_str() {
                            active.insert(name.to_string());
                        }
                    }
                }
            }
            let encoded = serde_json::to_string(&result)?;
            let bounded: String = encoded.chars().take(MAX_TOOL_PREVIEW).collect();
            let bounded = if bounded.len() < encoded.len() {
                format!("Result preview truncated; request a smaller page.\n{bounded}")
            } else {
                bounded
            };
            tool_activity.push(json!({"tool": name,"arguments":args,"result":bounded}));
            messages.push(provider.tool_result(&call, name, bounded)?);
        }
    }
    Err(anyhow!("agent reached the 8-round investigation limit"))
}

fn normalize_tool_arguments(value: &Value) -> Value {
    match value {
        Value::String(encoded) => serde_json::from_str(encoded).unwrap_or(Value::Null),
        value => value.clone(),
    }
}

fn matching_evidence(result: &Value, expected_target: &str) -> (Vec<Value>, Option<u64>) {
    let records = result
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| {
            serde_json::from_value::<crate::api::evidence::EvidenceRecord>(value.clone())
                .ok()
                .filter(|record| record.target_sha256 == expected_target)
                .map(|record| (value.clone(), record))
        })
        .collect::<Vec<_>>();
    let static_address = records
        .iter()
        .flat_map(|(_, record)| &record.locations)
        .find_map(|location| location.static_address.map(|address| address.get()));
    (
        records.into_iter().map(|(value, _)| value).collect(),
        static_address,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Scripted {
        messages: Vec<Value>,
        index: usize,
    }
    impl ChatProvider for Scripted {
        fn complete(&mut self, _: &[Value], tools: &[Value]) -> Result<Value> {
            if self.index == 0 {
                assert!(tools.len() <= 12);
            }
            let value = self.messages[self.index].clone();
            self.index += 1;
            Ok(value)
        }
    }
    #[test]
    fn conversation_executes_analysis_and_rejects_project_mutation() {
        let bytes = crate::formats::fixture::pe_with_driver();
        let bin = crate::formats::analyze("fixture.exe", &bytes).unwrap();
        let db = crate::db::Db::default();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 200_000, &db);
        let session = Session {
            bin,
            bytes,
            db,
            an,
            code_analyzed: true,
        };
        let mut ledger = Investigation::new("fixture");
        ledger
            .append(Role::Analyst, "Inspect the target".into(), vec![])
            .unwrap();
        let mut provider = Scripted {
            messages: vec![
                json!({"role":"assistant","tool_calls":[{"function":{"name":"session_status","arguments":{}}},{"function":{"name":"set_name","arguments":{"address":"0x140001000","name":"changed"}}}]}),
                json!({"role":"assistant","content":"Evidence is insufficient."}),
            ],
            index: 0,
        };
        let mut activity = Vec::new();
        let result = converse(&mut provider, &session, &ledger, |message| {
            activity.push(message.to_string())
        })
        .unwrap();
        assert_eq!(result["assistant"], "Evidence is insufficient.");
        assert_eq!(result["evidence"].as_array().unwrap().len(), 1);
        assert!(result["tool_activity"][1]["result"]
            .as_str()
            .unwrap()
            .contains("unavailable"));
        assert!(activity
            .iter()
            .any(|value| value == "Running session_status"));
        let mut empty = Scripted {
            messages: vec![json!({"role":"assistant","content":""})],
            index: 0,
        };
        assert!(converse(&mut empty, &session, &ledger, |_| {}).is_err());
        let mut discovering = Scripted {
            messages: vec![
                json!({"role":"assistant","tool_calls":[{"function":{"name":"discover_investigation_tools","arguments":{"task":"strings"}}}]}),
                json!({"role":"assistant","tool_calls":[{"function":{"name":"strings","arguments":{"query":"","limit":1}}}]}),
                json!({"role":"assistant","content":"Inspected string evidence."}),
            ],
            index: 0,
        };
        let discovery = converse(&mut discovering, &session, &ledger, |_| {}).unwrap();
        assert!(!discovery["tool_activity"][1]["result"]
            .as_str()
            .unwrap()
            .contains("unavailable"));
    }

    #[test]
    fn live_navigation_ignores_evidence_for_another_target() {
        use crate::address::StaticVa;
        use crate::api::evidence::{EvidenceKind, EvidenceLocation, EvidenceRecord};

        let wrong = EvidenceRecord::new(
            "wrong-target",
            "test",
            EvidenceKind::StaticAnalysis,
            "foreign location",
            vec![EvidenceLocation {
                static_address: Some(StaticVa(0x41414141)),
                ..EvidenceLocation::default()
            }],
            vec![],
            vec![],
        );
        let (records, address) = matching_evidence(&json!({"evidence": [wrong]}), "current-target");
        assert!(records.is_empty());
        assert_eq!(address, None);
    }

    #[test]
    fn openai_tool_arguments_and_response_ids_are_normalized() {
        assert_eq!(
            normalize_tool_arguments(&json!(r#"{"selector":"main"}"#)),
            json!({"selector":"main"})
        );
        assert_eq!(normalize_tool_arguments(&json!("not json")), Value::Null);

        let provider = OpenAiCompatible {
            service: OpenAiService::OpenRouter,
            model: "test/model".into(),
            endpoint: "https://openrouter.ai/api/v1/chat/completions".into(),
            api_key: "not-sent".into(),
            site_url: None,
            app_name: None,
        };
        let message = provider
            .tool_result(
                &json!({"id":"call_123","function":{"name":"session_status"}}),
                "session_status",
                "{}".into(),
            )
            .unwrap();
        assert_eq!(message["tool_call_id"], "call_123");
        assert_eq!(message["role"], "tool");
        assert!(message.get("tool_name").is_none());
    }

    #[test]
    fn hosted_endpoints_require_encryption_except_for_localhost() {
        assert!(validate_remote_endpoint("https://example.test/v1/chat/completions").is_ok());
        assert!(validate_remote_endpoint("http://127.0.0.1:8080/v1/chat/completions").is_ok());
        assert!(validate_remote_endpoint("http://localhost:8080/v1/chat/completions").is_ok());
        assert!(validate_remote_endpoint("http://example.test/v1/chat/completions").is_err());
        assert!(validate_remote_endpoint("https://key@example.test/v1/chat/completions").is_err());
    }

    #[test]
    fn saved_tool_transcripts_are_compacted_before_a_new_request() {
        struct MeasuringProvider {
            request_bytes: usize,
            history_messages: usize,
        }
        impl ChatProvider for MeasuringProvider {
            fn complete(&mut self, messages: &[Value], tools: &[Value]) -> Result<Value> {
                self.request_bytes = serde_json::to_vec(&json!({
                    "messages": messages,
                    "tools": tools
                }))?
                .len();
                self.history_messages = messages.len();
                Ok(json!({"role":"assistant","content":"compacted"}))
            }
        }

        let bytes = crate::formats::fixture::pe_with_driver();
        let bin = crate::formats::analyze("fixture.exe", &bytes).unwrap();
        let db = crate::db::Db::default();
        let an = crate::analysis::engine::analyze(&bin, &bytes, 200_000, &db);
        let session = Session {
            bin,
            bytes,
            db,
            an,
            code_analyzed: true,
        };
        let mut ledger = Investigation::new("fixture");
        for index in 0..20 {
            ledger
                .append(Role::Tool, "tool transcript ".repeat(700), vec![])
                .unwrap();
            ledger
                .append(
                    Role::Analyst,
                    format!("question {index}: {}", "focused context ".repeat(500)),
                    vec![],
                )
                .unwrap();
        }
        let mut provider = MeasuringProvider {
            request_bytes: 0,
            history_messages: 0,
        };
        let result = converse(&mut provider, &session, &ledger, |_| {}).unwrap();
        assert_eq!(result["assistant"], "compacted");
        assert!(provider.request_bytes < MAX_CONTEXT);
        assert!(provider.history_messages < ledger.messages.len());
    }

    #[test]
    fn openai_compatible_transport_sends_secret_header_and_parses_message() {
        if crate::providers::process::find_on_path("curl").is_none() {
            return;
        }
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let read = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..read]);
                if read == 0 || request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(headers.contains("authorization: bearer test-secret"));
            assert!(headers.contains("content-type: application/json"));
            let body = r#"{"choices":[{"message":{"role":"assistant","content":"ready"}}]}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let mut provider = OpenAiCompatible {
            service: OpenAiService::Compatible,
            model: "test/model".into(),
            endpoint: format!("http://{address}/v1/chat/completions"),
            api_key: "test-secret".into(),
            site_url: None,
            app_name: None,
        };
        let message = provider
            .complete(&[json!({"role":"user","content":"hello"})], &[])
            .unwrap();
        server.join().unwrap();
        assert_eq!(message["content"], "ready");
    }
}
