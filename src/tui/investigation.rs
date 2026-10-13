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
        let mut provider = match crate::agent::Ollama::from_environment() {
            Ok(provider) => provider,
            Err(error) => {
                self.investigation_activity = error.to_string();
                return;
            }
        };
        let path = self.bin.path.clone();
        let database = self
            .db
            .path()
            .map(|path| path.to_string_lossy().into_owned());
        let expected = crate::analysis::hashes::sha256_hex(&self.bytes);
        let ledger = self.investigation.clone();
        let activity = std::sync::Arc::new(std::sync::Mutex::new("Preparing model context".into()));
        self.investigation_live_activity = Some(activity.clone());
        let cancellation = crate::api::execution::CancellationToken::default();
        self.investigation_cancellation = Some(cancellation.clone());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| {
                let session = crate::workspace::Session::open(
                    &path,
                    database.as_deref(),
                    crate::ANALYSIS_BUDGET,
                    "investigation agent",
                )?;
                if crate::analysis::hashes::sha256_hex(&session.bytes) != expected {
                    anyhow::bail!("workspace changed; reload before starting the agent");
                }
                crate::agent::converse_cancellable(
                    &mut provider,
                    &session,
                    &ledger,
                    &cancellation,
                    |message| {
                        if let Ok(mut current) = activity.lock() {
                            *current = message.into();
                        }
                    },
                )
            })();
            let _ = sender.send(result);
        });
        self.investigation_worker = Some(receiver);
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
                let session = crate::workspace::Session::open(
                    &path,
                    database.as_deref(),
                    crate::ANALYSIS_BUDGET,
                    "investigation",
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
        self.investigation_cancellation = None;
        self.investigation_live_activity = None;
        match result {
            Err(error) => self.investigation_activity = format!("Failed: {error}"),
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
                        self.investigation_activity =
                            "Completed; evidence and tool response saved".into();
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
                self.status = format!("Saved investigation question #{id}");
                if std::env::var_os("KNIFE_AGENT_MODEL").is_some() {
                    self.start_investigation_agent();
                }
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
            self.investigation_open = false;
            self.execute_command(&format!("goto 0x{:x}", address.get()));
        } else {
            self.status = "This evidence has no static code location".into();
        }
    }
}
