//! # agent-scope-a2a
//!
//! An enforcing proxy for the [Agent2Agent (A2A)](https://a2a-protocol.org) protocol, the
//! counterpart of the MCP gateway for agent-to-agent calls:
//!
//! * `GET /.well-known/agent-card.json` returns the upstream agent card with only the skills the
//!   calling principal may use (`a2a_skill` catalog entries), and points `url` at the proxy.
//! * `message/send` and `message/stream` must name the skill in `metadata.skillId` (on the
//!   params or the message). The call is checked with `Action::a2a_skill(..)`; missing skill = deny.
//!   The skill's arguments are `metadata.arguments` plus the message text as `text`.
//! * `tasks/get`, `tasks/cancel`, `tasks/resubscribe` are only allowed for the principal that
//!   created the task (no task hijacking across users or agents).
//! * Every decision is audited; a failing sink denies.
//!
//! Delegation works as everywhere in agent-scope: a calling agent presents a token whose `act`
//! chain records who delegated to it, and every agent in the chain must hold the skill's scopes.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_scope_audit::{args_hmac, AuditSink};
use agent_scope_core::json::{parse_strict, Limits};
use agent_scope_core::{Action, Context, Effect, Engine, Principal};
use agent_scope_identity::{now_unix, Verifier};
use agent_scope_mcp::jsonrpc;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

pub const CARD_PATH: &str = "/.well-known/agent-card.json";

pub struct A2aProxyConfig {
    /// Base URL of the upstream A2A agent (its JSON-RPC endpoint).
    pub upstream_url: String,
    /// Where to fetch the upstream agent card; defaults to `<upstream>/.well-known/agent-card.json`.
    pub upstream_card_url: Option<String>,
    /// Public URL of this proxy (written into the filtered agent card).
    pub public_url: String,
    /// Catalog prefix for skills, e.g. `research.` → `research.deep_search`.
    pub skill_prefix: String,
    /// Credential the proxy presents upstream. The caller's token is never forwarded.
    pub upstream_token: Option<String>,
}

struct Inner {
    cfg: A2aProxyConfig,
    engine: Arc<Engine>,
    verifier: Arc<Verifier>,
    audit: Arc<dyn AuditSink>,
    http: reqwest::Client,
    /// task id → principal identity key
    tasks: Mutex<HashMap<String, String>>,
    hmac_key: Vec<u8>,
}

#[derive(Clone)]
pub struct A2aProxy(Arc<Inner>);

impl A2aProxy {
    pub fn new(cfg: A2aProxyConfig, engine: Arc<Engine>, verifier: Arc<Verifier>, audit: Arc<dyn AuditSink>, hmac_key: Vec<u8>) -> Self {
        Self(Arc::new(Inner {
            cfg,
            engine,
            verifier,
            audit,
            http: reqwest::Client::builder().timeout(Duration::from_secs(120)).build().unwrap_or_default(),
            tasks: Mutex::new(HashMap::new()),
            hmac_key,
        }))
    }

    pub fn router(&self) -> Router {
        Router::new().route(CARD_PATH, get(card)).route("/", post(rpc)).with_state(self.clone())
    }

    async fn principal(&self, headers: &HeaderMap) -> Result<Principal, Response> {
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "bearer token required").into_response())?;
        self.0.verifier.verify(token, now_unix()).await.map_err(|e| {
            let _ = self.0.audit.record("token_rejected", json!({"code": e.code(), "adapter": "a2a"}));
            (StatusCode::UNAUTHORIZED, "invalid token").into_response()
        })
    }

    async fn upstream_card(&self) -> Result<Value, String> {
        let url =
            self.0.cfg.upstream_card_url.clone().unwrap_or_else(|| format!("{}{CARD_PATH}", self.0.cfg.upstream_url.trim_end_matches('/')));
        let r = self.0.http.get(url).send().await.map_err(|e| e.to_string())?;
        r.json().await.map_err(|e| e.to_string())
    }

    fn skill_action(&self, skill: &str, args: Value) -> Action {
        Action::a2a_skill(format!("{}{skill}", self.0.cfg.skill_prefix), args)
    }

    fn audit(&self, p: &Principal, action: &Action, effect: Effect, rule: &str, reason: &str, version: &str) -> bool {
        let fields = json!({
            "subject": p.subject.id, "agent": p.agent, "act": p.act, "effect": effect, "rule": rule, "reason": reason,
            "policy_version": version, "adapter": "a2a",
            "action": {"kind": action.kind.as_str(), "name": action.name, "args_hmac": args_hmac(&self.0.hmac_key, &action.args)},
        });
        self.0.audit.record("decision", fields).is_ok()
    }

    async fn forward(&self, msg: &Value) -> Result<Value, String> {
        let mut r = self.0.http.post(&self.0.cfg.upstream_url).header("content-type", "application/json").body(msg.to_string());
        if let Some(t) = &self.0.cfg.upstream_token {
            r = r.bearer_auth(t);
        }
        let resp = r.send().await.map_err(|e| e.to_string())?;
        let text = resp.text().await.map_err(|e| e.to_string())?;
        // Streaming upstreams answer with SSE; collect the events into one response.
        if text.trim_start().starts_with("data:") || text.contains("\ndata:") {
            let events = agent_scope_mcp::sse::parse(&text);
            return events.into_iter().last().ok_or_else(|| "empty event stream".into());
        }
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }
}

/// Collect the text parts of an A2A message.
fn message_text(msg: &Value) -> String {
    msg.get("parts")
        .and_then(Value::as_array)
        .map(|parts| parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

async fn card(State(proxy): State<A2aProxy>, headers: HeaderMap) -> Response {
    let mut card = match proxy.upstream_card().await {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("upstream agent card unavailable: {e}")).into_response(),
    };
    // Anonymous callers see the card without skills; authenticated ones see their skills.
    let principal = proxy.principal(&headers).await.ok();
    let ctx = Context::default();
    let skills: Vec<Value> = match (&principal, card.get("skills").and_then(Value::as_array)) {
        (Some(p), Some(all)) => all
            .iter()
            .filter(|s| {
                let id = s.get("id").and_then(Value::as_str).unwrap_or("");
                proxy.0.engine.visible(p, &proxy.skill_action(id, Value::Null), &ctx)
            })
            .cloned()
            .collect(),
        _ => vec![],
    };
    card["skills"] = Value::Array(skills);
    card["url"] = json!(proxy.0.cfg.public_url);
    Json(card).into_response()
}

fn rpc_error(id: Value, code: i64, msg: &str) -> Response {
    (StatusCode::OK, Json(jsonrpc::error(id, code, msg))).into_response()
}

async fn rpc(State(proxy): State<A2aProxy>, headers: HeaderMap, body: Bytes) -> Response {
    let p = match proxy.principal(&headers).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        return rpc_error(Value::Null, jsonrpc::PARSE_ERROR, "body is not UTF-8");
    };
    let msg = match parse_strict(text, Limits::default()) {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(jsonrpc::error(Value::Null, jsonrpc::PARSE_ERROR, &format!("rejected: {e}"))))
                .into_response()
        }
    };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let engine = &proxy.0.engine;

    match method {
        "message/send" | "message/stream" => {
            let message = params.get("message").cloned().unwrap_or(Value::Null);
            let skill = params
                .pointer("/metadata/skillId")
                .or_else(|| message.pointer("/metadata/skillId"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let Some(skill) = skill else {
                return rpc_error(id, jsonrpc::FORBIDDEN, "A skill must be named in metadata.skillId.");
            };
            let mut args = params.pointer("/metadata/arguments").cloned().unwrap_or_else(|| json!({}));
            if let Value::Object(m) = &mut args {
                m.insert("text".into(), json!(message_text(&message)));
            }
            let action = proxy.skill_action(&skill, args);
            let d = engine.check(&p, &action, &Context::default());
            if !proxy.audit(&p, &action, d.effect, &d.rule, &d.reason, &d.policy_version) {
                return rpc_error(id, jsonrpc::FORBIDDEN, "This action is not permitted.");
            }
            if d.effect != Effect::Allow {
                // Human approval is not part of A2A; require_approval is denied here.
                let text =
                    if d.effect == Effect::RequireApproval { "This skill requires human approval." } else { d.model_message.as_str() };
                return rpc_error(id, jsonrpc::FORBIDDEN, text);
            }
            // message/stream is answered as a single (final) response.
            let mut fwd = msg.clone();
            fwd["method"] = json!("message/send");
            match proxy.forward(&fwd).await {
                Ok(resp) => {
                    if let Some(task_id) =
                        resp.pointer("/result/id").and_then(Value::as_str).filter(|_| resp.pointer("/result/kind") == Some(&json!("task")))
                    {
                        if let Ok(mut t) = proxy.0.tasks.lock() {
                            t.insert(task_id.to_string(), p.identity_key());
                        }
                    }
                    Json(resp).into_response()
                }
                Err(e) => rpc_error(id, jsonrpc::UPSTREAM_ERROR, &format!("upstream agent unavailable: {e}")),
            }
        }
        "tasks/get" | "tasks/cancel" | "tasks/resubscribe" => {
            let task = params.get("id").and_then(Value::as_str).unwrap_or("");
            let owner = proxy.0.tasks.lock().ok().and_then(|t| t.get(task).cloned());
            if owner.as_deref() != Some(p.identity_key().as_str()) {
                let action = Action::a2a_skill(format!("{}tasks", proxy.0.cfg.skill_prefix), json!({"task": task}));
                proxy.audit(
                    &p,
                    &action,
                    Effect::Deny,
                    "a2a.task_owner",
                    "task belongs to another principal or is unknown",
                    engine.version(),
                );
                return rpc_error(id, jsonrpc::FORBIDDEN, "This action is not permitted.");
            }
            match proxy.forward(&msg).await {
                Ok(resp) => Json(resp).into_response(),
                Err(e) => rpc_error(id, jsonrpc::UPSTREAM_ERROR, &format!("upstream agent unavailable: {e}")),
            }
        }
        _ => rpc_error(id, jsonrpc::METHOD_NOT_FOUND, "method not supported by the agent-scope A2A proxy"),
    }
}
