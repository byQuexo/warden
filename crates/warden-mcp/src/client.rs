//! An MCP client for Streamable HTTP and stdio servers.
//!
//! One session per credential: the gateway talks to an upstream with a per-user token,
//! so sessions are keyed by the bearer token. The wire protocol is `rmcp`'s. Server→client
//! requests that arrive while a call is in flight are answered with an error and reported
//! in [`Outcome::blocked`].

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use rmcp::model::{
    ClientCapabilities, ClientConfig, ClientRequest, CustomRequest, CustomResult, Implementation, ProtocolVersion, ServerResult,
};
use rmcp::service::{RunningService, ServiceError, ServiceExt};
use rmcp::transport::streamable_http_client::{StreamableHttpClientTransport, StreamableHttpClientTransportConfig};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::RoleClient;
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::sync::Mutex;

use crate::block::BlockingHandler;
use crate::http::RecordingHttp;
use crate::order::{OrderGate, OrderTransport};
use crate::sse;
use crate::stdio::StdioSpec;
use crate::LATEST_PROTOCOL_VERSION;

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

pub struct RawResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    pub messages: Vec<Value>,
}

struct Live {
    running: RunningService<RoleClient, BlockingHandler>,
    session: Arc<StdMutex<Option<String>>>,
    blocked: Arc<StdMutex<Vec<String>>>,
    notes: Arc<StdMutex<Vec<Value>>>,
    call: Mutex<()>,
    alive: AtomicBool,
}

pub struct McpClient {
    url: String,
    http: reqwest::Client,
    sessions: Mutex<HashMap<String, Arc<Live>>>,
    timeout: Duration,
    stdio: Option<StdioSpec>,
    info: ClientConfig,
}

impl McpClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_timeout(url, Duration::from_secs(300))
    }

    pub fn with_timeout(url: impl Into<String>, timeout: Duration) -> Self {
        Self {
            url: url.into(),
            http: http_client(timeout),
            sessions: Mutex::new(HashMap::new()),
            timeout,
            stdio: None,
            info: client_info(),
        }
    }

    /// A client for a local stdio MCP server. The process is started on first use and
    /// restarted if it exits. Bearer tokens are ignored: the server is not on the network.
    pub fn stdio(spec: StdioSpec) -> Self {
        let mut c = Self::new(format!("stdio:{}", spec.command));
        c.stdio = Some(spec);
        c
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// POST one JSON-RPC message and collect all messages of the response (JSON or SSE).
    ///
    /// This is not the session state machine. It exists so a caller can send a body the
    /// SDK will not construct (duplicate object keys) and can read the HTTP status.
    /// The session id comes from [`Self::session_id`].
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
        if self.stdio.is_some() {
            return None;
        }
        let key = bearer.unwrap_or("");
        let guard = self.sessions.lock().await;
        guard.get(key).and_then(|live| live.session.lock().ok().and_then(|g| g.clone()))
    }

    /// Send a request, initializing a session first if needed.
    pub async fn call(&self, bearer: Option<&str>, method: &str, params: Value) -> Result<Outcome, ClientError> {
        let live = self.live(bearer).await?;
        match self.call_on(&live, method, params.clone()).await {
            Err(e) if transport_closed(&e) => {
                live.alive.store(false, Ordering::SeqCst);
                let live = self.live(bearer).await?;
                self.call_on(&live, method, params).await
            }
            other => other,
        }
    }

    async fn call_on(&self, live: &Live, method: &str, params: Value) -> Result<Outcome, ClientError> {
        let _guard = live.call.lock().await;
        if let Ok(mut b) = live.blocked.lock() {
            b.clear();
        }
        if let Ok(mut n) = live.notes.lock() {
            n.clear();
        }
        let params = if params.is_null() { None } else { Some(params) };
        let request = ClientRequest::CustomRequest(CustomRequest::new(method, params));
        let sent = tokio::time::timeout(self.timeout, live.running.send_request(request)).await;
        let result = match sent {
            Err(_) => return Err(ClientError::Protocol(format!("{method}: no response in time"))),
            Ok(Ok(ServerResult::CustomResult(CustomResult(v)))) => Ok(v),
            Ok(Ok(other)) => match serde_json::to_value(&other) {
                Ok(v) => Ok(v),
                Err(e) => return Err(ClientError::Protocol(e.to_string())),
            },
            Ok(Err(ServiceError::McpError(e))) => Err((i64::from(e.code.0), e.message.to_string())),
            Ok(Err(e)) => return Err(ClientError::Protocol(e.to_string())),
        };
        let blocked = live.blocked.lock().map(|mut b| std::mem::take(&mut *b)).unwrap_or_default();
        let notifications = live.notes.lock().map(|mut n| std::mem::take(&mut *n)).unwrap_or_default();
        Ok(Outcome { result, blocked, notifications })
    }

    /// Call a paginated `*/list` method and concatenate `key` arrays.
    ///
    /// The page cap is Warden's. A cursor that never ends must not pin a gateway
    /// worker; fifty pages is already more than a catalog this process will enforce.
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

    async fn live(&self, bearer: Option<&str>) -> Result<Arc<Live>, ClientError> {
        if self.stdio.is_some() {
            return self.stdio_live().await;
        }
        let key = bearer.unwrap_or("").to_string();
        if let Some(live) = self.sessions.lock().await.get(&key).cloned() {
            if live.alive.load(Ordering::SeqCst) {
                return Ok(live);
            }
        }
        let live = Arc::new(self.connect_http(bearer).await?);
        self.sessions.lock().await.insert(key, live.clone());
        Ok(live)
    }

    async fn connect_http(&self, bearer: Option<&str>) -> Result<Live, ClientError> {
        let session = Arc::new(StdMutex::new(None));
        let http = RecordingHttp::new(self.http.clone(), session.clone());
        let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str()).reinit_on_expired_session(true);
        if let Some(token) = bearer {
            config = config.auth_header(token.to_string());
        }
        let transport = StreamableHttpClientTransport::with_client(http, config);
        self.serve(transport, session).await
    }

    async fn stdio_live(&self) -> Result<Arc<Live>, ClientError> {
        let key = "stdio".to_string();
        if let Some(live) = self.sessions.lock().await.get(&key).cloned() {
            if live.alive.load(Ordering::SeqCst) {
                return Ok(live);
            }
        }
        let spec = self.stdio.clone().ok_or_else(|| ClientError::Http("stdio client has no command".into()))?;
        let live = Arc::new(self.connect_stdio(&spec).await?);
        self.sessions.lock().await.insert(key, live.clone());
        Ok(live)
    }

    async fn connect_stdio(&self, spec: &StdioSpec) -> Result<Live, ClientError> {
        let command = spec.command.clone();
        let cmd = Command::new(&spec.command).configure(|cmd| {
            cmd.args(&spec.args).kill_on_drop(true);
            for (k, v) in &spec.env {
                cmd.env(k, v);
            }
        });
        let (transport, _) = TokioChildProcess::builder(cmd)
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| ClientError::Http(format!("cannot start `{command}`: {e}")))?;
        self.serve(transport, Arc::new(StdMutex::new(None))).await
    }

    async fn serve<T>(&self, transport: T, session: Arc<StdMutex<Option<String>>>) -> Result<Live, ClientError>
    where
        T: rmcp::transport::Transport<RoleClient> + 'static,
    {
        let gate = Arc::new(OrderGate::new());
        let handler = BlockingHandler::new(self.info.clone(), Arc::clone(&gate));
        let blocked = handler.blocked_handle();
        let notes = handler.notes_handle();
        let running = handler.serve(OrderTransport::new(transport, gate)).await.map_err(|e| ClientError::Protocol(e.to_string()))?;
        Ok(Live { running, session, blocked, notes, call: Mutex::new(()), alive: AtomicBool::new(true) })
    }
}

fn client_info() -> ClientConfig {
    // LATEST is 2026-07-28, which has no initialize handshake. Offer the newest
    // revision that still does; the server may negotiate down.
    ClientConfig::new(ClientCapabilities::default(), Implementation::new("warden", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
}

fn http_client(timeout: Duration) -> reqwest::Client {
    // Idle pooling stalls the next POST on Linux when the previous body was not
    // fully consumed. The SDK disables it for the same reason.
    reqwest::Client::builder().timeout(timeout).pool_max_idle_per_host(0).build().unwrap_or_else(|_| reqwest::Client::new())
}

fn transport_closed(err: &ClientError) -> bool {
    match err {
        ClientError::Protocol(m) | ClientError::Http(m) => m.contains("Transport closed") || m.contains("stdio server exited"),
        ClientError::Status(_, _) => false,
    }
}
