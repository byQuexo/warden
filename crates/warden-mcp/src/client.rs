//! An MCP client for Streamable HTTP and stdio servers.
//!
//! One session per credential: the gateway talks to an upstream with a per-user token,
//! so sessions are keyed by the bearer token. The wire protocol is `rmcp`'s. Server→client
//! requests that arrive while a call is in flight are answered with an error and reported
//! in [`Outcome::blocked`].

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};
use std::time::{Duration, Instant};

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

/// A session nobody has used for this long is closed and forgotten. Exchanged
/// credentials rotate, so without this every old token would keep a live session.
const IDLE_TTL: Duration = Duration::from_secs(15 * 60);

/// Upper bound on establishing a TCP/TLS connection to an HTTP upstream.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests that are safe to send again after the connection died mid-call: the spec
/// defines them as reads. Anything else (above all `tools/call`) may already have run
/// upstream, so it is reported as failed rather than replayed.
const REPLAY_SAFE: &[&str] = &[
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
    "completion/complete",
];

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
    last_used: StdMutex<Instant>,
}

impl Live {
    /// The service loop is still running and nothing marked this session as unusable.
    fn is_live(&self) -> bool {
        self.alive.load(Ordering::SeqCst) && !self.running.is_closed() && !self.running.peer().is_transport_closed()
    }

    /// Stop using this session and shut its service loop down.
    fn kill(&self) {
        self.alive.store(false, Ordering::SeqCst);
        self.running.cancellation_token().cancel();
    }

    fn touch(&self) {
        *lock(&self.last_used) = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        lock(&self.last_used).elapsed()
    }
}

/// One credential's session. The async lock is held while connecting, so concurrent
/// first calls for the same credential share one `initialize`.
type Slot = Arc<Mutex<Option<Arc<Live>>>>;

/// How one attempt on a session ended, when it did not produce an [`Outcome`].
enum Attempt {
    /// The session was already dead; nothing was sent.
    NotSent,
    /// The connection closed after the request was sent. The upstream may have run it.
    Closed,
    Failed(ClientError),
}

pub struct McpClient {
    url: String,
    /// For [`Self::post_raw`]: one request, whole body read, so pooling and a total timeout are fine.
    http: reqwest::Client,
    /// For the SDK transport, which also holds long-lived SSE streams. See [`sdk_http_client`].
    sdk_http: reqwest::Client,
    sessions: StdMutex<HashMap<String, Slot>>,
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
            http: reqwest::Client::builder().timeout(timeout).build().unwrap_or_else(|_| reqwest::Client::new()),
            sdk_http: sdk_http_client(),
            sessions: StdMutex::new(HashMap::new()),
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
        let slot = lock(&self.sessions).get(bearer.unwrap_or("")).cloned()?;
        let guard = slot.lock().await;
        guard.as_ref().and_then(|live| lock(&live.session).clone())
    }

    /// Send a request, initializing a session first if needed.
    ///
    /// A dead session is replaced before sending. If the connection dies after the
    /// request went out, only [`REPLAY_SAFE`] methods are sent again.
    pub async fn call(&self, bearer: Option<&str>, method: &str, params: Value) -> Result<Outcome, ClientError> {
        let live = self.live(bearer).await?;
        match self.call_on(&live, method, params.clone()).await {
            Ok(o) => Ok(o),
            Err(Attempt::Failed(e)) => Err(e),
            Err(Attempt::Closed) if !REPLAY_SAFE.contains(&method) => Err(closed(method)),
            Err(Attempt::NotSent | Attempt::Closed) => {
                let live = self.live(bearer).await?;
                match self.call_on(&live, method, params).await {
                    Ok(o) => Ok(o),
                    Err(Attempt::Failed(e)) => Err(e),
                    Err(Attempt::NotSent | Attempt::Closed) => Err(closed(method)),
                }
            }
        }
    }

    async fn call_on(&self, live: &Live, method: &str, params: Value) -> Result<Outcome, Attempt> {
        let _guard = live.call.lock().await;
        if !live.is_live() {
            return Err(Attempt::NotSent);
        }
        live.touch();
        lock(&live.blocked).clear();
        lock(&live.notes).clear();
        let params = if params.is_null() { None } else { Some(params) };
        let request = ClientRequest::CustomRequest(CustomRequest::new(method, params));
        let sent = tokio::time::timeout(self.timeout, live.running.send_request(request)).await;
        let result = match sent {
            Err(_) => {
                // The upstream (or this session's worker) is stuck. Don't hand the same
                // session to the next caller.
                live.kill();
                return Err(Attempt::Failed(ClientError::Protocol(format!("{method}: no response in time"))));
            }
            Ok(Ok(ServerResult::CustomResult(CustomResult(v)))) => Ok(v),
            Ok(Ok(other)) => match serde_json::to_value(&other) {
                Ok(v) => Ok(v),
                Err(e) => return Err(Attempt::Failed(ClientError::Protocol(e.to_string()))),
            },
            Ok(Err(ServiceError::McpError(e))) => Err((i64::from(e.code.0), e.message.to_string())),
            Ok(Err(ServiceError::TransportClosed)) => {
                live.kill();
                return Err(Attempt::Closed);
            }
            Ok(Err(e)) => {
                if !live.is_live() {
                    live.kill();
                    return Err(Attempt::Closed);
                }
                return Err(Attempt::Failed(ClientError::Protocol(e.to_string())));
            }
        };
        let blocked = std::mem::take(&mut *lock(&live.blocked));
        let notifications = std::mem::take(&mut *lock(&live.notes));
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

    /// The live session for this credential, connecting if there is none.
    async fn live(&self, bearer: Option<&str>) -> Result<Arc<Live>, ClientError> {
        let key = if self.stdio.is_some() { "" } else { bearer.unwrap_or("") };
        let slot = self.slot(key);
        let mut guard = slot.lock().await;
        if let Some(live) = guard.as_ref().filter(|l| l.is_live()) {
            return Ok(Arc::clone(live));
        }
        let live = Arc::new(match &self.stdio {
            Some(spec) => self.connect_stdio(spec).await?,
            None => self.connect_http(bearer).await?,
        });
        // Replacing a dead session drops it, which cancels its service loop.
        *guard = Some(Arc::clone(&live));
        Ok(live)
    }

    /// The slot for `key`, after forgetting sessions that are dead or idle.
    fn slot(&self, key: &str) -> Slot {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|k, slot| k == key || keep(slot));
        Arc::clone(sessions.entry(key.to_string()).or_default())
    }

    async fn connect_http(&self, bearer: Option<&str>) -> Result<Live, ClientError> {
        let session = Arc::new(StdMutex::new(None));
        let http = RecordingHttp::new(self.sdk_http.clone(), session.clone());
        let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str()).reinit_on_expired_session(true);
        if let Some(token) = bearer {
            config = config.auth_header(token.to_string());
        }
        let transport = StreamableHttpClientTransport::with_client(http, config);
        self.serve(transport, session).await
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
        let serving = handler.serve(OrderTransport::new(transport, gate));
        let running = tokio::time::timeout(self.timeout, serving)
            .await
            .map_err(|_| ClientError::Protocol("initialize: no response in time".into()))?
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        Ok(Live {
            running,
            session,
            blocked,
            notes,
            call: Mutex::new(()),
            alive: AtomicBool::new(true),
            last_used: StdMutex::new(Instant::now()),
        })
    }
}

/// Whether eviction should keep this slot. A slot someone else holds (connecting, or
/// about to) is kept; an empty, dead or idle one is dropped, which closes its session.
fn keep(slot: &Slot) -> bool {
    if Arc::strong_count(slot) > 1 {
        return true;
    }
    match slot.try_lock() {
        Ok(guard) => guard.as_ref().is_some_and(|live| live.is_live() && live.idle_for() < IDLE_TTL),
        Err(_) => true,
    }
}

fn closed(method: &str) -> ClientError {
    ClientError::Http(format!("{method}: upstream connection closed before it answered"))
}

/// Lock a std mutex, recovering the data if a panicking thread poisoned it. Every
/// critical section here is a plain read or write, so the data is never half-updated.
fn lock<T>(m: &StdMutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn client_info() -> ClientConfig {
    // LATEST is 2026-07-28, which has no initialize handshake. Offer the newest
    // revision that still does; the server may negotiate down.
    ClientConfig::new(ClientCapabilities::default(), Implementation::new("warden", env!("CARGO_PKG_VERSION")))
        .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
}

/// The reqwest client behind the SDK transport.
///
/// No total timeout: the same client carries the standalone GET SSE stream, which is
/// meant to stay open. Per-request deadlines are enforced in [`McpClient::call_on`].
/// Idle pooling is off, as in `rmcp`'s own default client: reusing a connection whose
/// SSE body was not fully read stalls the next POST (TCP delayed ACK on Linux).
fn sdk_http_client() -> reqwest::Client {
    reqwest::Client::builder().connect_timeout(CONNECT_TIMEOUT).pool_max_idle_per_host(0).build().unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use super::REPLAY_SAFE;

    #[test]
    fn side_effects_are_never_replayed() {
        assert!(!REPLAY_SAFE.contains(&"tools/call"));
        assert!(!REPLAY_SAFE.contains(&"resources/subscribe"));
        assert!(REPLAY_SAFE.contains(&"tools/list"));
    }
}
