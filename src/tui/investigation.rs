use super::App;
use crate::api::investigation::Role;

impl App {
    pub fn refresh_investigation(&mut self) {
        if self.investigation_worker.is_some() {
            self.status = "Interrupt active work before refreshing the investigation".into();
            return;
        }
        let result = self
            .db
            .path()
            .ok_or_else(|| anyhow::anyhow!("workspace has no persistent database"))
            .and_then(|path| {
                crate::api::investigation::Investigation::load(
                    &path.with_extension("investigation.json"),
                    &self.db.sha256,
                )
            });
        match result {
            Ok(ledger) => {
                self.investigation = ledger;
                self.investigation_selection = 0;
                self.investigation_open = true;
                self.status = "Investigation refreshed from disk".into();
            }
            Err(error) => self.status = format!("Cannot refresh investigation: {error}"),
        }
    }

    pub fn start_investigation_agent(&mut self) {
        if self.investigation_worker.is_some() {
            self.status =
                "Question saved; interrupt the current investigation before starting another"
                    .into();
            return;
        }
        let mut provider = match crate::agent::ConfiguredProvider::from_config(&self.agent_config) {
            Ok(provider) => provider,
            Err(error) => {
                self.investigation_activity = error.to_string();
                self.investigation_open = true;
                return;
            }
        };
        self.investigation_activity = format!("Connecting to {}", provider.label());
        let path = self.bin.path.clone();
        let database = self
            .db
            .path()
            .map(|path| path.to_string_lossy().into_owned());
        let expected = crate::analysis::hashes::sha256_hex(&self.bytes);
        let ledger = self.investigation.clone();
        let selection = if let Some(function) = self.current_function() {
            format!(
                "function {} at static VA 0x{:x}; cursor static VA {}",
                function.name,
                function.addr.saturating_add(self.base),
                self.cursor_addr()
                    .map(|address| format!("0x{:x}", address.saturating_add(self.base)))
                    .unwrap_or_else(|| "unavailable".into())
            )
        } else if self.raw_file {
            let offset = self
                .lines
                .get(self.cursor)
                .map(super::Line::addr)
                .or(self.cur)
                .unwrap_or(0);
            format!("raw file view at file offset 0x{offset:x}")
        } else {
            self.cursor_addr()
                .map(|address| format!("data at static VA 0x{:x}", address + self.base))
                .unwrap_or_else(|| "no address selected".into())
        };
        let ui_context = Some(format!(
            "{} / {} target; {selection}",
            self.bin.format.label(),
            self.bin.arch.label()
        ));
        let activity = std::sync::Arc::new(std::sync::Mutex::new("Preparing model context".into()));
        self.investigation_live_activity = Some(activity.clone());
        let cancellation = crate::api::execution::CancellationToken::default();
        self.investigation_cancellation = Some(cancellation.clone());
        let (sender, receiver) = std::sync::mpsc::channel();
        let (progress_sender, progress_receiver) = std::sync::mpsc::channel();
        self.investigation_agent_events = Some(progress_receiver);
        std::thread::spawn(move || {
            let result = (|| {
                let session = crate::workspace::Session::open_any(
                    &path,
                    database.as_deref(),
                    crate::ANALYSIS_BUDGET,
                )?;
                if crate::analysis::hashes::sha256_hex(&session.bytes) != expected {
                    anyhow::bail!("workspace changed; reload before starting the agent");
                }
                crate::agent::converse_with_ui_context(
                    &mut provider,
                    &session,
                    &ledger,
                    &cancellation,
                    ui_context.as_deref(),
                    |event| {
                        if let crate::agent::AgentEvent::Activity(message) = &event {
                            if let Ok(mut current) = activity.lock() {
                                *current = message.clone();
                            }
                        }
                        let _ = progress_sender.send(event);
                    },
                )
            })();
            let _ = sender.send(result);
        });
        self.investigation_worker = Some(receiver);
    }

    /// Start one of the common reverse-engineering workflows without making
    /// the analyst formulate a long prompt every time.
    pub fn start_quick_investigation(&mut self, target_wide: bool) {
        if self.investigation_worker.is_some() {
            self.status = "Interrupt the active agent before starting another analysis".into();
            return;
        }
        self.investigation_question(quick_investigation_prompt(target_wide).into());
    }

    /// Re-run the latest saved analyst request after a provider or transport
    /// failure. This intentionally does not append a duplicate question.
    pub fn retry_last_investigation(&mut self) {
        if self.investigation_worker.is_some() {
            self.status = "The agent is already working; Ctrl+C interrupts it".into();
            return;
        }
        if !self
            .investigation
            .messages
            .iter()
            .rev()
            .any(|message| message.role == Role::Analyst && !message.text.trim().is_empty())
        {
            self.status =
                "No previous agent question to retry; type a message or press Alt+A/Alt+T".into();
            return;
        }
        self.investigation_open = true;
        self.investigation_focused = true;
        self.investigation_zoomed = true;
        self.investigation_evidence_detail = false;
        self.investigation_message_offset = 0;
        self.investigation_chat_follow = true;
        self.investigation_activity = "Retrying the latest question".into();
        self.start_investigation_agent();
        self.investigation_message_scroll = crate::tui::render::investigation_scroll_max(self);
    }

    pub fn start_agent_setup(&mut self) {
        if self.investigation_worker.is_some() {
            self.status = "Interrupt active agent work before changing its provider".into();
            return;
        }
        self.investigation_open = true;
        self.investigation_focused = true;
        self.investigation_zoomed = true;
        self.agent_setup_choices = vec![
            "openrouter".into(),
            "ollama".into(),
            "openai".into(),
            "compatible".into(),
        ];
        self.agent_setup_selection = self
            .agent_setup_choices
            .iter()
            .position(|choice| choice == &self.agent_config.provider)
            .unwrap_or(0);
        self.status =
            "Provider/model are remembered; API keys use the operating-system credential vault"
                .into();
        self.ask(super::Ask::AgentProvider);
    }

    pub fn agent_setup_provider(&mut self, provider: String) {
        let provider = provider.trim().to_ascii_lowercase();
        if !matches!(
            provider.as_str(),
            "ollama" | "openrouter" | "openai" | "compatible" | "openai-compatible"
        ) {
            self.status = "Provider must be ollama, openrouter, openai, or compatible".into();
            self.ask(super::Ask::AgentProvider);
            return;
        }
        let provider = if provider == "openai-compatible" {
            "compatible".into()
        } else {
            provider
        };
        if provider != self.agent_config.provider {
            self.agent_config.provider = provider;
            self.agent_config.reload_api_key_from_vault();
        }
        if self.agent_config.provider == "ollama" && self.agent_config.base_url.is_empty() {
            self.agent_config.base_url = "http://127.0.0.1:11434".into();
        }
        self.agent_setup_choices =
            model_choices(&self.agent_config.provider, &self.agent_config.model);
        self.agent_setup_selection = self
            .agent_setup_choices
            .iter()
            .position(|choice| choice == &self.agent_config.model)
            .unwrap_or(0);
        self.status = "Choose with ↑/↓ or type an exact provider model identifier".into();
        self.ask(super::Ask::AgentModel);
    }

    pub fn agent_setup_model(&mut self, model: String) {
        let model = model.trim();
        if model.is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            self.status = "Model must be a non-empty identifier under 257 characters".into();
            self.ask(super::Ask::AgentModel);
            return;
        }
        self.agent_config.model = model.into();
        match self.agent_config.provider.as_str() {
            "ollama" | "compatible" => {
                self.status = if self.agent_config.provider == "ollama" {
                    "Confirm the local Ollama URL".into()
                } else {
                    "Enter the OpenAI-compatible API base URL".into()
                };
                self.ask(super::Ask::AgentBaseUrl);
            }
            _ => {
                self.status = if self.agent_config.has_api_key() {
                    "Enter a replacement API key, or leave blank to keep the loaded key".into()
                } else {
                    "Enter the API key; input is masked and saved in your OS credential vault"
                        .into()
                };
                self.ask(super::Ask::AgentApiKey);
            }
        }
    }

    pub fn agent_setup_base_url(&mut self, base_url: String) {
        self.agent_config.base_url = base_url.trim().to_string();
        if self.agent_config.provider == "ollama" {
            self.finish_agent_setup();
        } else {
            self.status = if self.agent_config.has_api_key() {
                "Enter a replacement API key, or leave blank to keep the loaded key".into()
            } else {
                "Enter the API key; input is masked and saved in your OS credential vault".into()
            };
            self.ask(super::Ask::AgentApiKey);
        }
    }

    pub fn agent_setup_api_key(&mut self, api_key: String) {
        let changed = !api_key.is_empty();
        if !api_key.is_empty() {
            self.agent_config.api_key = api_key;
        }
        if changed {
            if let Err(error) = self.agent_config.save_api_key() {
                let preference_error = self.agent_config.save_preferences().err();
                self.finish_agent_setup_without_status();
                self.status = match preference_error {
                    Some(preference_error) => format!(
                        "Session ready, but preferences ({preference_error}) and OS vault key ({error}) could not be saved"
                    ),
                    None => format!(
                        "Provider/model remembered, but the key is session-only because the OS vault failed: {error}"
                    ),
                };
                return;
            }
        }
        self.finish_agent_setup();
    }

    fn finish_agent_setup(&mut self) {
        let saved = self.agent_config.save_preferences();
        self.finish_agent_setup_without_status();
        if let Err(error) = saved {
            self.status = format!("Provider ready, but preferences could not be saved: {error}");
        }
    }

    fn finish_agent_setup_without_status(&mut self) {
        self.investigation_activity = self.agent_config.status();
        self.status = match crate::agent::ConfiguredProvider::from_config(&self.agent_config) {
            Ok(_) => "Agent provider ready and remembered; press F6 and type to chat".into(),
            Err(error) => format!("Provider setup incomplete: {error}"),
        };
    }

    pub fn run_investigation_tool(&mut self, input: &str) {
        if self.investigation_worker.is_some() {
            self.status =
                "An investigation tool is already running; :interrupt discards its result".into();
            return;
        }
        let (name, args) = input.split_once(' ').unwrap_or((input, "{}"));
        let args: serde_json::Value = match serde_json::from_str::<serde_json::Value>(args) {
            Ok(value) if value.is_object() => value,
            _ => {
                self.status = "Use :run-tool NAME {JSON arguments}".into();
                return;
            }
        };
        if !crate::tools::read_catalog()
            .iter()
            .any(|operation| operation.name == name)
        {
            self.status = "Investigation tools must be registered analysis reads".into();
            return;
        }
        let path = self.bin.path.clone();
        let database = self
            .db
            .path()
            .map(|path| path.to_string_lossy().into_owned());
        let expected = crate::analysis::hashes::sha256_hex(&self.bytes);
        let name = name.to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        self.investigation_activity = format!("Running {name}");
        self.investigation_open = true;
        std::thread::spawn(move || {
            let result = (|| {
                let session = crate::workspace::Session::open_any(
                    &path,
                    database.as_deref(),
                    crate::ANALYSIS_BUDGET,
                )?;
                if crate::analysis::hashes::sha256_hex(&session.bytes) != expected {
                    anyhow::bail!("workspace changed since this TUI opened; reload before collecting evidence");
                }
                crate::tools::dispatch(&session, &name, &args)
            })();
            let _ = sender.send(result);
        });
        self.investigation_worker = Some(receiver);
    }

    pub fn poll_investigation(&mut self) {
        let events = self
            .investigation_agent_events
            .as_ref()
            .map(|receiver| receiver.try_iter().take(96).collect::<Vec<_>>())
            .unwrap_or_default();
        for event in events {
            self.apply_agent_event(event);
        }
        if let Some(activity) = &self.investigation_live_activity {
            if let Ok(activity) = activity.lock() {
                self.investigation_activity = activity.clone();
            }
        }
        let Some(receiver) = &self.investigation_worker else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => Err(anyhow::anyhow!("investigation worker disconnected")),
        };
        self.investigation_worker = None;
        self.investigation_agent_events = None;
        self.investigation_cancellation = None;
        self.investigation_live_activity = None;
        match result {
            Err(error) => {
                self.investigation_activity = format!("Failed: {error}");
                if self.investigation_chat_follow {
                    self.investigation_message_scroll =
                        crate::tui::render::investigation_scroll_max(self);
                }
            }
            Ok(value) => {
                let mut next = self.investigation.clone();
                let saved = (|| {
                    let mut links = Vec::new();
                    if let Some(records) =
                        value.get("evidence").and_then(serde_json::Value::as_array)
                    {
                        for value in records {
                            let record: crate::api::evidence::EvidenceRecord =
                                serde_json::from_value(value.clone())?;
                            links.push(record.id.clone());
                            next.record(record)?;
                        }
                    }
                    if let Some(activity) = value
                        .get("tool_activity")
                        .and_then(serde_json::Value::as_array)
                    {
                        for call in activity {
                            let text: String = serde_json::to_string_pretty(call)?
                                .chars()
                                .take(7000)
                                .collect();
                            next.append(Role::Tool, text, vec![])?;
                        }
                    }
                    let (role, text) = if let Some(answer) =
                        value.get("assistant").and_then(serde_json::Value::as_str)
                    {
                        (Role::Assistant, answer.to_string())
                    } else {
                        (Role::Tool, serde_json::to_string_pretty(&value)?)
                    };
                    // Full evidence records are retained separately. Keep the
                    // conversation readable and within the text bound.
                    let text: String = text.chars().take(7000).collect();
                    next.append(role, text, links)?;
                    let path = self
                        .db
                        .path()
                        .ok_or_else(|| anyhow::anyhow!("workspace has no persistent database"))?
                        .with_extension("investigation.json");
                    next.save(&path)
                })();
                match saved {
                    Ok(()) => {
                        self.investigation = next;
                        self.investigation_evidence_detail = false;
                        self.investigation_message_offset = 0;
                        self.investigation_chat_follow = true;
                        self.investigation_message_scroll =
                            crate::tui::render::investigation_scroll_max(self);
                        self.investigation_activity = if value
                            .get("limited")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false)
                        {
                            format!(
                                "Partial answer saved: {}",
                                value
                                    .get("limitation")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap_or("agent tool budget reached")
                            )
                        } else {
                            "Completed; evidence and tool response saved".into()
                        };
                    }
                    Err(error) => {
                        self.investigation_activity = format!("Could not persist result: {error}")
                    }
                }
            }
        }
    }

    pub fn investigation_question(&mut self, question: String) {
        let mut next = self.investigation.clone();
        let result = (|| {
            let id = next.ask(question.clone())?;
            next.append(Role::Analyst, question, vec![])?;
            let path = self
                .db
                .path()
                .ok_or_else(|| anyhow::anyhow!("this workspace has no persistent database"))?
                .with_extension("investigation.json");
            next.save(&path)?;
            Ok::<_, anyhow::Error>(id)
        })();
        match result {
            Ok(id) => {
                self.investigation = next;
                self.investigation_open = true;
                self.investigation_focused = true;
                self.investigation_zoomed = true;
                self.investigation_evidence_detail = false;
                self.investigation_message_offset = 0;
                self.investigation_chat_follow = true;
                self.status = format!("Saved investigation question #{id}");
                self.start_investigation_agent();
                self.investigation_message_scroll =
                    crate::tui::render::investigation_scroll_max(self);
            }
            Err(error) => self.status = format!("Cannot save question: {error}"),
        }
    }

    pub fn follow_investigation_evidence(&mut self) {
        let location = self
            .investigation
            .evidence
            .values()
            .nth(self.investigation_selection)
            .and_then(|record| {
                record
                    .locations
                    .iter()
                    .find_map(|location| location.static_address)
            });
        if let Some(address) = location {
            self.execute_command(&format!("goto 0x{:x}", address.get()));
            self.investigation_focused = false;
            self.investigation_follow = false;
        } else {
            self.status = "This evidence has no static code location".into();
        }
    }

    pub fn apply_agent_event(&mut self, event: crate::agent::AgentEvent) {
        match event {
            crate::agent::AgentEvent::Activity(message) => self.investigation_activity = message,
            crate::agent::AgentEvent::ToolCompleted {
                name,
                static_address,
            } => {
                self.investigation_activity = format!("Completed {name}");
                if self.investigation_open && self.investigation_follow {
                    if let Some(address) = static_address {
                        self.execute_command(&format!("goto 0x{address:x}"));
                    }
                }
            }
        }
    }
}

fn model_choices(provider: &str, current: &str) -> Vec<String> {
    let suggestions: &[&str] = match provider {
        "openrouter" => &[
            "z-ai/glm-5.3-flash",
            "z-ai/glm-5.3-flashx",
            "openrouter/auto",
        ],
        "ollama" => &["qwen3", "qwen3-coder", "llama3.3"],
        "openai" => &["gpt-5.4"],
        _ => &[],
    };
    let mut choices = Vec::new();
    if !current.trim().is_empty() {
        choices.push(current.trim().to_string());
    }
    for suggestion in suggestions {
        if !choices.iter().any(|choice| choice == suggestion) {
            choices.push((*suggestion).to_string());
        }
    }
    choices
}

fn quick_investigation_prompt(target_wide: bool) -> &'static str {
    if target_wide {
        "Triage the complete target. Identify its format and security properties; inspect suspicious imports, strings, functions, embedded content, and likely validation or decryption logic; follow the strongest cross-references; then give prioritized next steps. Clearly separate observed evidence, inference, limitations, and unknowns."
    } else {
        "Analyze the current Knife selection in context. Explain what it does, trace its inputs, outputs, callers, callees, referenced strings, and validation or decryption behavior where supported. Clearly separate observed evidence, inference, limitations, and unknowns."
    }
}

#[cfg(test)]
mod tests {
    use super::quick_investigation_prompt;

    #[test]
    fn quick_prompts_request_evidence_and_honest_limits() {
        for prompt in [
            quick_investigation_prompt(false),
            quick_investigation_prompt(true),
        ] {
            assert!(prompt.contains("observed evidence"));
            assert!(prompt.contains("inference"));
            assert!(prompt.contains("limitations"));
            assert!(prompt.contains("unknowns"));
        }
        assert!(quick_investigation_prompt(true).contains("complete target"));
        assert!(quick_investigation_prompt(false).contains("current Knife selection"));
    }
}
