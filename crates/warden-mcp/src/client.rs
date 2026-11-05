//! An MCP client for Streamable HTTP and stdio servers.
//!
//! One session per credential: the gateway talks to an upstream with a per-user token,
//! so sessions are keyed by the bearer token. Server→client requests that arrive in a
//! response stream are answered with an error and reported in [`Outcome::blocked`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::jsonrpc;
use crate::stdio::{StdioConn, StdioSpec};
use crate::{sse, LATEST_PROTOCOL_VERSION};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("upstream unreachable: {0}")]
    Http(String),
    #[error("upstream returned HTTP {0}: {1}")]
    Status(u16, String),
    #[error("upstream protocol error: {0}")]
    Protocol(String),
}

/// Result of one request.
#[derive(Debug)]
pub struct Outcome {
    /// `Ok(result)` or `Err((code, message))` from the JSON-RPC response.
    pub result: Result<Value, (i64, String)>,
    /// Server→client request methods that were blocked.
    pub blocked: Vec<String>,
    /// Notifications received while waiting (e.g. progress).
    pub notifications: Vec<Value>,
}

pub struct McpClient {
    url: String,
    http: reqwest::Client,
    sessions: Mutex<HashMap<String, Option<String>>>,
    next_id: AtomicI64,
    client_name: String,
    timeout: Duration,
    stdio: Option<(StdioSpec, Mutex<Option<std::sync::Arc<StdioConn>>>)>,
}

pub struct RawResponse {
    pub status: u16,
    pub headers: HeaderMap,
    pub messages: Vec<Value>,
}

impl McpClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_timeout(url, Duration::from_secs(300))
    }

    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::builder().timeout(timeout).build().unwrap_or_default(),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicI64::new(1),
            client_name: "warden".into(),
            timeout,
            stdio: None,
        }
    }

    /// A client for a local stdio MCP server. The process is started on first use and
    /// restarted if it exits. Bearer tokens are ignored: the server is not on the network.
    pub fn stdio(spec: StdioSpec) -> Self {
        let mut c = Self::new(format!("stdio:{}", spec.command));
        c.stdio = Some((spec, Mutex::new(None)));
        c
    }

    async fn call_stdio(
        &self,
        spec: &StdioSpec,
        slot: &Mutex<Option<std::sync::Arc<StdioConn>>>,
        method: &str,
        params: Value,
    ) -> Result<Outcome, ClientError> {
        let conn = {
            let mut guard = slot.lock().await;
            match guard.as_ref().filter(|c| c.is_alive()) {
                Some(c) => c.clone(),
                None => {
                    let c = StdioConn::spawn(spec).await?;
                    let init = json!({
                        "protocolVersion": LATEST_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": self.client_name, "version": env!("CARGO_PKG_VERSION")}
                    });
                    let (resp, _) = c.request(self.id(), "initialize", init, self.timeout).await?;
                    if let Some(e) = resp.get("error") {
                        return Err(ClientError::Protocol(format!("initialize failed: {e}")));
                    }
                    c.notify("notifications/initialized", json!({})).await?;
                    *guard = Some(c.clone());
                    c
                }
            }
        };
        let (resp, blocked) = conn.request(self.id(), method, params, self.timeout).await?;
        let result = match (resp.get("result"), resp.get("error")) {
            (Some(r), _) => Ok(r.clone()),
            (None, Some(e)) => Err((
                e.get("code").and_then(Value::as_i64).unwrap_or(jsonrpc::INTERNAL_ERROR),
                e.get("message").and_then(Value::as_str).unwrap_or("error").to_string(),
            )),
            _ => Err((jsonrpc::INTERNAL_ERROR, "empty response".into())),
        };
        Ok(Outcome { result, blocked, notifications: vec![] })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn id(&self) -> Value {
        Value::from(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// POST one JSON-RPC message and collect all messages of the response (JSON or SSE).
    pub async fn post_raw(&self, bearer: Option<&str>, session: Option<&str>, body: &Value) -> Result<RawResponse, ClientError> {
        let mut req = self
            .http
            .post(&self.url)
            .header(ACCEPT, "application/json, text/event-stream")
            .header(CONTENT_TYPE, "application/json")
            .header("mcp-protocol-version", LATEST_PROTOCOL_VERSION)
            .body(body.to_string());
        if let Some(b) = bearer {
            req = req.header(AUTHORIZATION, format!("Bearer {b}"));
        }
        if let Some(s) = session {
            req = req.header("mcp-session-id", s);
        }
        let resp = req.send().await.map_err(|e| ClientError::Http(e.to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let is_sse = headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|c| c.starts_with("text/event-stream"));
        let text = resp.text().await.map_err(|e| ClientError::Http(e.to_string()))?;
        let messages = if text.trim().is_empty() {
            vec![]
        } else if is_sse {
            sse::parse(&text)
        } else {
            match serde_json::from_str::<Value>(&text) {
                Ok(Value::Array(a)) => a,
                Ok(v) => vec![v],
                Err(_) if status >= 400 => vec![],
                Err(e) => return Err(ClientError::Protocol(format!("invalid JSON: {e}"))),
            }
        };
        Ok(RawResponse { status, headers, messages })
    }

    /// The session id currently used for this bearer token, if any.
    pub async fn session_id(&self, bearer: Option<&str>) -> Option<String> {
        self.sessions.lock().await.get(bearer.unwrap_or("")).cloned().flatten()
    }

    async fn initialize(&self, bearer: Option<&str>) -> Result<Option<String>, ClientError> {
        let body = jsonrpc::request(
            self.id(),
            "initialize",
            json!({
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self.client_name, "version": env!("CARGO_PKG_VERSION")}
            }),
        );
        let r = self.post_raw(bearer, None, &body).await?;
        if r.status >= 400 {
            return Err(ClientError::Status(r.status, describe(&r.messages)));
        }
        let session = r.headers.get("mcp-session-id").and_then(|v| v.to_str().ok()).map(str::to_string);
        if let Some(e) = r.messages.iter().find_map(|m| m.get("error")) {
            return Err(ClientError::Protocol(format!("initialize failed: {e}")));
        }
        let _ = self.post_raw(bearer, session.as_deref(), &jsonrpc::notification("notifications/initialized", json!({}))).await?;
        self.sessions.lock().await.insert(bearer.unwrap_or("").to_string(), session.clone());
        Ok(session)
    }

    /// Send a request, initializing a session first if needed.
    pub async fn call(&self, bearer: Option<&str>, method: &str, params: Value) -> Result<Outcome, ClientError> {
        if let Some((spec, slot)) = &self.stdio {
            return self.call_stdio(spec, slot, method, params).await;
        }
        let key = bearer.unwrap_or("").to_string();
        for attempt in 0..2 {
            let existing = self.sessions.lock().await.get(&key).cloned();
            let session = match existing {
                Some(s) => s,
                None => self.initialize(bearer).await?,
            };
            let id = self.id();
            let r = self.post_raw(bearer, session.as_deref(), &jsonrpc::request(id.clone(), method, params.clone())).await?;
            if r.status == 404 && session.is_some() && attempt == 0 {
                // Session expired upstream: start a new one once.
                self.sessions.lock().await.remove(&key);
                continue;
            }
            if r.status >= 400 {
                return Err(ClientError::Status(r.status, describe(&r.messages)));
            }
            return self.collect(bearer, session.as_deref(), &id, r.messages).await;
        }
        Err(ClientError::Protocol("session could not be re-established".into()))
    }

    async fn collect(&self, bearer: Option<&str>, session: Option<&str>, id: &Value, messages: Vec<Value>) -> Result<Outcome, ClientError> {
        let mut blocked = Vec::new();
        let mut notifications = Vec::new();
        let mut result = None;
        for m in messages {
            match jsonrpc::classify(&m) {
                jsonrpc::Message::Request { id: rid, method, .. } => {
                    blocked.push(method.to_string());
                    let reply = jsonrpc::error(rid.clone(), jsonrpc::METHOD_NOT_FOUND, "blocked by warden gateway");
                    let _ = self.post_raw(bearer, session, &reply).await;
                }
                jsonrpc::Message::Notification { .. } => notifications.push(m),
                jsonrpc::Message::Response if m.get("id") == Some(id) => {
                    result = Some(match (m.get("result"), m.get("error")) {
                        (Some(r), _) => Ok(r.clone()),
                        (None, Some(e)) => Err((
                            e.get("code").and_then(Value::as_i64).unwrap_or(jsonrpc::INTERNAL_ERROR),
                            e.get("message").and_then(Value::as_str).unwrap_or("error").to_string(),
                        )),
                        _ => Err((jsonrpc::INTERNAL_ERROR, "empty response".into())),
                    });
                }
                _ => {}
            }
        }
        let result = result.ok_or_else(|| ClientError::Protocol("no response for request id".into()))?;
        Ok(Outcome { result, blocked, notifications })
    }

    /// Call a paginated `*/list` method and concatenate `key` arrays.
    pub async fn list_all(&self, bearer: Option<&str>, method: &str, key: &str) -> Result<Vec<Value>, ClientError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..50 {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let o = self.call(bearer, method, params).await?;
            let r = o.result.map_err(|(c, m)| ClientError::Protocol(format!("{method}: {c} {m}")))?;
            if let Some(Value::Array(items)) = r.get(key) {
                out.extend(items.iter().cloned());
            }
            cursor = r.get("nextCursor").and_then(Value::as_str).map(str::to_string);
            if cursor.is_none() {
                return Ok(out);
            }
        }
        Err(ClientError::Protocol(format!("{method}: too many pages")))
    }
}

fn describe(messages: &[Value]) -> String {
    messages.iter().find_map(|m| m.pointer("/error/message").and_then(Value::as_str).map(str::to_string)).unwrap_or_default()
}
