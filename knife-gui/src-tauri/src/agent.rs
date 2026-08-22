//! The agent pane: a model that can read this binary through knife's own tools.
//!
//! knife already exposes its analysis to agents over MCP (`knife mcp`). This is
//! the same idea inside the window: the model asks for a disassembly or an
//! audit, the request runs locally against the open `Session`, and the answer
//! goes back as a tool result. The analysis never leaves the engine; only the
//! text of what it produced does.
//!
//! Three deliberate limits:
//!
//! * **Read-only.** The tool list has no writes. The model can argue that a
//!   function should be called `parse_header`; applying that is the analyst's
//!   click. An agent that renames things on its own is very hard to unpick
//!   later, and its mistakes look exactly like your own work.
//! * **Consent per binary.** Code from the open file is sent to a third party.
//!   That is fine for a CTF binary and possibly a firing offence for a client's,
//!   so it is off until enabled for a specific file, remembered by hash.
//! * **The key lives in the OS keyring**, never in this repo, a config file, or
//!   the webview.

use crate::state::AppState;
use anyhow::{anyhow, Result};
use futures_util::StreamExt;
use reknife::analysis::{engine, ir};
use reknife::listing;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use tauri::{Emitter, State};

const SERVICE: &str = "knife-gui";
const ACCOUNT: &str = "openrouter";
const ENDPOINT: &str = "https://openrouter.ai/api/v1/chat/completions";

/// Set by `agent_cancel` to stop the turn in flight. One turn runs at a
/// time, so a single flag is enough; `agent_ask` clears it at the start.
static CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How many rounds of tool calls to allow before requiring an answer.
///
/// Reading a binary genuinely takes several steps — list the functions, look at
/// one, follow a call, check what reaches it — so this is not a tight budget.
/// What matters more is what happens at the end of it: see `force_answer`.
const MAX_TOOL_ROUNDS: usize = 16;

/// Rows returned to the model from a listing tool. Enough to reason about,
/// bounded so a large function cannot blow the context in one call.
const TOOL_ROW_LIMIT: usize = 400;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// What the pane shows after a turn: the reply, and what the model looked at
/// to produce it.
#[derive(Serialize)]
pub struct AgentTurn {
    pub reply: String,
    /// Tool calls made, in order, for the transcript.
    pub steps: Vec<AgentStep>,
    /// The full message list, to be sent back as history next turn.
    pub history: Vec<ChatMessage>,
    /// Edits the model proposed. Applying one is the analyst's click; the agent
    /// never writes.
    pub suggestions: Vec<Suggestion>,
}

/// An edit the model recommends. Recording it is read-only; the frontend turns
/// it into an Apply button that calls the ordinary validated write command.
#[derive(Serialize, Clone)]
pub struct Suggestion {
    /// "rename" or "prototype".
    pub kind: &'static str,
    /// Function name or hex address the edit applies to.
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub returns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Vec<String>>,
    /// Why the model proposed it, for the analyst deciding whether to apply.
    pub reason: String,
}

#[derive(Serialize, Clone)]
pub struct AgentStep {
    pub tool: String,
    pub args: String,
    /// Truncated for display; the model saw the whole thing.
    pub preview: String,
}

// ── key handling ────────────────────────────────────────────────────────────

fn entry() -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT).map_err(|e| anyhow!("keyring unavailable: {e}"))
}

#[tauri::command]
pub fn agent_set_key(key: String) -> Result<(), String> {
    let key = key.trim().to_string();
    if key.is_empty() {
        return entry()
            .and_then(|e| e.delete_credential().map_err(|e| anyhow!("{e}")))
            .map_err(|e| e.to_string());
    }
    entry()
        .and_then(|e| e.set_password(&key).map_err(|e| anyhow!("{e}")))
        .map_err(|e| e.to_string())
}

/// Whether a key is stored. The key itself is never returned to the frontend.
#[tauri::command]
pub fn agent_has_key() -> bool {
    entry()
        .and_then(|e| e.get_password().map_err(|e| anyhow!("{e}")))
        .is_ok()
}

fn read_key() -> Result<String> {
    entry()?
        .get_password()
        .map_err(|_| anyhow!("no OpenRouter key stored: add one in the agent pane"))
}

// ── the tools the model may call ────────────────────────────────────────────

/// The tool schema, in OpenAI function-calling form. Every one of these is a
/// read: nothing here can change the database.
fn tool_schema() -> Value {
    let f = |name: &str, desc: &str, props: Value, required: Vec<&str>| {
        json!({
            "type": "function",
            "function": {
                "name": name,
                "description": desc,
                "parameters": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                }
            }
        })
    };
    json!([
        f(
            "info",
            "Format, architecture, entry point, section count, function \
           and finding counts for the binary under analysis.",
            json!({}),
            vec![]
        ),
        f(
            "list_functions",
            "Recovered functions, optionally filtered by a \
           substring of the name. Returns address, name and incoming call count.",
            json!({"filter": {"type": "string"}, "limit": {"type": "integer"}}),
            vec![]
        ),
        f(
            "disassemble",
            "Disassembly of one function. The selector is a \
           function name or a hex address.",
            json!({"selector": {"type": "string"}}),
            vec!["selector"]
        ),
        f(
            "decompile",
            "Decompiled pseudocode for one function.",
            json!({"selector": {"type": "string"}}),
            vec!["selector"]
        ),
        f(
            "audit",
            "Ranked findings: dangerous call sites whose arguments look \
           exploitable, worst first, each with the reason and whether it is \
           reachable from an entry point.",
            json!({"limit": {"type": "integer"}}),
            vec![]
        ),
        f(
            "xrefs",
            "What references an address or function.",
            json!({"selector": {"type": "string"}}),
            vec!["selector"]
        ),
        f(
            "paths_to",
            "Call chains that reach a function from the entry point \
           or an export. Empty means nothing was found to reach it.",
            json!({"selector": {"type": "string"}}),
            vec!["selector"]
        ),
        f(
            "strings",
            "String literals whose text contains a query, with how \
           many instructions reference each.",
            json!({"query": {"type": "string"}}),
            vec!["query"]
        ),
    ])
}

/// Run one tool against the open target. Every arm is a read.
fn run_tool(state: &State<AppState>, name: &str, args: &Value) -> Result<String> {
    let s = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let n = |k: &str, d: usize| {
        args.get(k)
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .unwrap_or(d)
            .min(TOOL_ROW_LIMIT)
    };

    state.read(|l| {
        let an = &l.session.an;
        let bin = &l.session.bin;
        Ok(match name {
            "info" => format!(
                "{} {} {}-bit, entry 0x{:x}, {} sections, {} functions ({} named), {} findings",
                bin.format.label(),
                bin.arch.label(),
                bin.bits,
                bin.entry,
                bin.sections.len(),
                an.functions.len(),
                an.functions.iter().filter(|f| f.named).count(),
                l.findings.len()
            ),
            "list_functions" => {
                let needle = s("filter").to_lowercase();
                let limit = n("limit", 60);
                let mut out = String::new();
                for f in an
                    .functions
                    .iter()
                    .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
                    .take(limit)
                {
                    out.push_str(&format!(
                        "0x{:x} {} ({} refs, {} bytes)\n",
                        f.addr, f.name, f.incoming, f.size
                    ));
                }
                if out.is_empty() {
                    "no match".into()
                } else {
                    out
                }
            }
            "disassemble" | "decompile" => {
                let sel = s("selector");
                let f = crate::commands::resolve(an, &sel)
                    .ok_or_else(|| anyhow!("nothing matches {sel}"))?;
                if name == "decompile" {
                    ir::decompile(an, bin, f, &l.strings, &l.session.db)
                        .iter()
                        .map(|x| x.text.clone())
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    listing::function(an, f, &l.session.db, l.base, &l.strings, l.hints.as_ref())
                        .iter()
                        .take(TOOL_ROW_LIMIT)
                        .map(|line| match line {
                            listing::Line::Label { text, .. } => text.clone(),
                            listing::Line::Insn {
                                addr,
                                mnemonic,
                                operands,
                                annot,
                                ..
                            } => format!(
                                "0x{addr:x}  {mnemonic} {operands}{}",
                                annot
                                    .as_ref()
                                    .map(|a| format!(
                                        "   ; {}",
                                        match a {
                                            listing::Annot::Note(t)
                                            | listing::Annot::Symbol(t)
                                            | listing::Annot::Local(t)
                                            | listing::Annot::Text(t)
                                            | listing::Annot::Hint(t) => t.clone(),
                                        }
                                    ))
                                    .unwrap_or_default()
                            ),
                            listing::Line::Data { addr, text } => format!("0x{addr:x}  {text}"),
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            "audit" => {
                let limit = n("limit", 40);
                let mut out = String::new();
                for f in l.findings.iter().take(limit) {
                    out.push_str(&format!(
                        "[{}] {} {} at 0x{:x} in {} {} — {}\n",
                        f.severity,
                        f.pattern,
                        f.api,
                        f.addr,
                        f.func.as_deref().unwrap_or("?"),
                        if f.reachable {
                            "(reachable)"
                        } else {
                            "(unproven)"
                        },
                        f.detail
                    ));
                }
                if out.is_empty() {
                    "no findings".into()
                } else {
                    out
                }
            }
            "xrefs" => {
                let sel = s("selector");
                let target = crate::commands::resolve(an, &sel)
                    .map(|f| f.addr)
                    .or_else(|| crate::commands::parse_addr(&sel).ok())
                    .ok_or_else(|| anyhow!("nothing matches {sel}"))?;
                match an.xrefs_to.get(&target) {
                    Some(refs) => refs
                        .iter()
                        .take(TOOL_ROW_LIMIT)
                        .map(|x| {
                            format!(
                                "0x{:x} {} in {}",
                                x.from,
                                x.kind.label(),
                                crate::commands::site_name(an, x.from)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n"),
                    None => "no references".into(),
                }
            }
            "paths_to" => {
                let sel = s("selector");
                let target = crate::commands::resolve(an, &sel)
                    .map(|f| f.addr)
                    .or_else(|| crate::commands::parse_addr(&sel).ok())
                    .ok_or_else(|| anyhow!("nothing matches {sel}"))?;
                let base = engine::display_base(bin);
                let mut roots: Vec<u64> = bin
                    .symbols
                    .iter()
                    .filter(|y| y.kind == reknife::model::SymKind::Export)
                    .map(|y| y.addr + base)
                    .collect();
                roots.push(bin.entry + base);
                let chains = an.paths_to(target, &roots, 8, false);
                if chains.is_empty() {
                    "nothing reaches it from an entry point or export".into()
                } else {
                    chains
                        .iter()
                        .map(|c| {
                            c.iter()
                                .map(|a| an.label(*a))
                                .collect::<Vec<_>>()
                                .join(" -> ")
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            "strings" => {
                let q = s("query").to_lowercase();
                let mut out = String::new();
                let mut shown = 0;
                for (addr, st) in l.strings.iter() {
                    if !st.text.to_lowercase().contains(&q) {
                        continue;
                    }
                    let refs = an.xrefs_to.get(addr).map_or(0, Vec::len);
                    out.push_str(&format!("0x{addr:x} ({refs} refs) {:?}\n", st.text));
                    shown += 1;
                    if shown >= 80 {
                        break;
                    }
                }
                if out.is_empty() {
                    "no literal matches".into()
                } else {
                    out
                }
            }
            other => return Err(anyhow!("unknown tool {other}")),
        })
    })
}

fn system_prompt(target: &str, is_driver: bool) -> String {
    let mut p = format!(
        "You are assisting a reverse engineer working on {target} inside knife, a static \
         binary analysis tool. Use the tools to read the binary rather than guessing; if you \
         have not looked at a function, say so instead of inventing its behaviour. Prefer \
         concrete evidence: addresses, call chains, the audit's own reasoning. You cannot \
         modify the analysis database; when something should be renamed or retyped, say what \
         and why, and the analyst will apply it. The binary is never executed. Answer as soon \
         as you can support an answer, and never repeat a tool call you have already made with \
         the same arguments, since it returns the same bytes."
    );
    if is_driver {
        p.push_str(
            " This target is a Windows kernel driver and the analyst is hunting local \
             privilege escalation through a vulnerable driver (BYOVD). Work the IOCTL attack \
             surface reachable from user mode: find the IRP dispatch and the DeviceIoControl \
             handler, decode each IOCTL code, and trace what its handler does with the input \
             buffer the caller controls. Flag classic LPE primitives and name the IOCTL that \
             reaches each: arbitrary read/write (MmMapIoSpace, MmMapLockedPagesSpecifyCache, \
             a copy whose address or length is caller-controlled), physical memory mapping \
             (PhysicalMemory device, ZwMapViewOfSection), MSR read/write (__readmsr / \
             __writemsr reachable from an IOCTL), process-token theft (PsLookupProcessByProcessId \
             then swapping the Token pointer), and any routine taking a user pointer with no \
             ProbeForRead or ProbeForWrite. For each candidate say the IOCTL, what the attacker \
             controls, and what the primitive grants. Use audit and paths_to to prove a \
             handler is reachable before calling it a finding.",
        );
    }
    p
}

fn emit(app: &tauri::AppHandle, payload: Value) {
    let _ = app.emit("knife://agent", payload);
}

/// Pull a human message out of an OpenRouter error body.
fn error_message(text: &str) -> String {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.chars().take(300).collect())
}

/// One reassembled streamed tool call.
#[derive(Default, Clone)]
struct ToolAcc {
    id: String,
    name: String,
    args: String,
}

/// Stream one completion, emitting a token event per content chunk, and return
/// the assembled text plus any tool calls the model asked for.
///
/// Streaming is the point of this pass: a turn can take many seconds of tool
/// round-trips, and a pane that shows nothing until it finishes reads as broken.
/// Here the answer types itself and each tool call surfaces as it lands.
async fn stream_once(
    client: &reqwest::Client,
    key: &str,
    app: &tauri::AppHandle,
    body: Value,
) -> Result<(String, Vec<ToolAcc>)> {
    let resp = client
        .post(ENDPOINT)
        .bearer_auth(key)
        .header("HTTP-Referer", "https://github.com/bl4ckr0ss3/knife")
        .header("X-Title", "knife")
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("request failed: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("{}", error_message(&text)).context(format!("HTTP {status}")));
    }

    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut content = String::new();
    let mut tools: Vec<ToolAcc> = Vec::new();

    while let Some(chunk) = stream.next().await {
        if CANCEL.load(std::sync::atomic::Ordering::Relaxed) {
            // Return what streamed so far rather than an error: a stop is a
            // choice, not a failure.
            break;
        }
        let bytes = chunk.map_err(|e| anyhow!("stream interrupted: {e}"))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));

        // Server-sent events: one JSON object per data line; [DONE] closes.
        while let Some(nl) = buf.find('\n') {
            let line: String = buf.drain(..=nl).collect();
            let line = line.trim();
            let Some(data) = line.strip_prefix("data:") else {
                continue;
            };
            let data = data.trim();
            if data.is_empty() || data == "[DONE]" {
                continue;
            }
            let Ok(v) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            if let Some(msg) = v
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
            {
                return Err(anyhow!("{msg}"));
            }
            let delta = v.pointer("/choices/0/delta").cloned().unwrap_or(json!({}));

            if let Some(t) = delta.get("content").and_then(Value::as_str) {
                if !t.is_empty() {
                    content.push_str(t);
                    emit(app, json!({ "kind": "token", "text": t }));
                }
            }
            if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
                for tc in calls {
                    let idx = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    while tools.len() <= idx {
                        tools.push(ToolAcc::default());
                    }
                    if let Some(id) = tc.get("id").and_then(Value::as_str) {
                        if !id.is_empty() {
                            tools[idx].id = id.to_string();
                        }
                    }
                    if let Some(f) = tc.get("function") {
                        if let Some(n) = f.get("name").and_then(Value::as_str) {
                            tools[idx].name.push_str(n);
                        }
                        if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                            tools[idx].args.push_str(a);
                        }
                    }
                }
            }
        }
    }
    Ok((content, tools))
}

#[tauri::command]
pub async fn agent_ask(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    model: String,
    question: String,
    history: Vec<ChatMessage>,
) -> Result<AgentTurn, String> {
    agent_turn(app, state, model, question, history)
        .await
        .map_err(|e| format!("{e:#}"))
}

async fn agent_turn(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    model: String,
    question: String,
    history: Vec<ChatMessage>,
) -> Result<AgentTurn> {
    let key = read_key()?;
    let (target, is_driver) = state
        .read(|l| {
            Ok((
                l.session.bin.path.clone(),
                reknife::analysis::driver::plausibly_a_driver(&l.session.bin),
            ))
        })
        .unwrap_or_else(|_| ("a binary".to_string(), false));

    let mut messages: Vec<ChatMessage> = Vec::new();
    if history.is_empty() {
        messages.push(ChatMessage {
            role: "system".into(),
            content: Some(system_prompt(&target, is_driver)),
            tool_calls: None,
            tool_call_id: None,
            name: None,
        });
    } else {
        messages.extend(history);
    }
    messages.push(ChatMessage {
        role: "user".into(),
        content: Some(question),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });

    CANCEL.store(false, std::sync::atomic::Ordering::Relaxed);
    let client = reqwest::Client::new();
    let mut steps: Vec<AgentStep> = Vec::new();
    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for _ in 0..MAX_TOOL_ROUNDS {
        emit(&app, json!({ "kind": "round" }));
        let body = json!({
            "model": model,
            "messages": messages,
            "tools": tool_schema(),
            "stream": true,
        });
        let (content, tools) = stream_once(&client, &key, &app, body).await?;

        let tool_calls_json = (!tools.is_empty()).then(|| {
            Value::Array(
                tools
                    .iter()
                    .map(|t| {
                        json!({
                            "id": t.id,
                            "type": "function",
                            "function": { "name": t.name, "arguments": t.args },
                        })
                    })
                    .collect(),
            )
        });
        messages.push(ChatMessage {
            role: "assistant".into(),
            content: (!content.is_empty()).then(|| content.clone()),
            tool_calls: tool_calls_json,
            tool_call_id: None,
            name: None,
        });

        if tools.is_empty() {
            emit(&app, json!({ "kind": "done" }));
            return Ok(AgentTurn {
                reply: content,
                steps,
                history: messages,
                suggestions,
            });
        }

        for t in &tools {
            emit(
                &app,
                json!({ "kind": "tool", "tool": t.name, "args": t.args }),
            );
            let args: Value = serde_json::from_str(&t.args).unwrap_or(json!({}));

            // The propose_* tools do not read or write; they record a suggestion
            // the analyst can apply with a click, preserving the read-only rule.
            if t.name == "propose_rename" || t.name == "propose_prototype" {
                let get = |k: &str| {
                    args.get(k)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                };
                let sel = get("selector");
                let func = get("function");
                let suggestion = if t.name == "propose_rename" {
                    Suggestion {
                        kind: "rename",
                        selector: sel,
                        new_name: Some(get("new_name")),
                        returns: None,
                        params: None,
                        reason: get("reason"),
                    }
                } else {
                    Suggestion {
                        kind: "prototype",
                        selector: func,
                        new_name: None,
                        returns: Some(get("returns")),
                        params: Some(
                            args.get("params")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(str::to_string))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        ),
                        reason: get("reason"),
                    }
                };
                emit(
                    &app,
                    json!({ "kind": "suggestion", "suggestion": suggestion }),
                );
                suggestions.push(suggestion);
                messages.push(ChatMessage {
                    role: "tool".into(),
                    content: Some("recorded; the analyst will decide whether to apply it".into()),
                    tool_calls: None,
                    tool_call_id: Some(t.id.clone()),
                    name: Some(t.name.clone()),
                });
                continue;
            }

            let signature = format!("{}{}", t.name, t.args);
            let result = if !seen.insert(signature) {
                "you already called this with the same arguments; the result is unchanged. \
                 Use what you have or call something different."
                    .to_string()
            } else {
                match run_tool(&state, &t.name, &args) {
                    Ok(text) => text,
                    Err(e) => format!("error: {e}"),
                }
            };
            emit(
                &app,
                json!({ "kind": "result", "tool": t.name,
                        "preview": result.chars().take(200).collect::<String>() }),
            );
            steps.push(AgentStep {
                tool: t.name.clone(),
                args: t.args.clone(),
                preview: result.chars().take(300).collect(),
            });
            messages.push(ChatMessage {
                role: "tool".into(),
                content: Some(result),
                tool_calls: None,
                tool_call_id: Some(t.id.clone()),
                name: Some(t.name.clone()),
            });
        }
    }

    // Out of rounds: answer from what it has rather than discarding the work.
    emit(&app, json!({ "kind": "round" }));
    messages.push(ChatMessage {
        role: "user".into(),
        content: Some(
            "Answer now from what you have read. Do not call more tools. If something is still \
             unknown, say what and why."
                .into(),
        ),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    let body =
        json!({ "model": model, "messages": messages, "tool_choice": "none", "stream": true });
    let (reply, _) = stream_once(&client, &key, &app, body).await?;
    emit(&app, json!({ "kind": "done" }));
    messages.push(ChatMessage {
        role: "assistant".into(),
        content: Some(reply.clone()),
        tool_calls: None,
        tool_call_id: None,
        name: None,
    });
    Ok(AgentTurn {
        reply,
        steps,
        history: messages,
        suggestions,
    })
}

/// Stop the turn currently running.
#[tauri::command]
pub fn agent_cancel() {
    CANCEL.store(true, std::sync::atomic::Ordering::Relaxed);
}
