//! Gateway state, builder and shared helpers.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use agent_scope_audit::{args_hmac, AuditSink};
use agent_scope_core::{Action, AttrValue, Context, Decision, Engine, KillSwitch, Principal, Sensitivity};
use agent_scope_identity::{AttributeResolver, Verifier};
use agent_scope_mcp::McpClient;
use chrono::Timelike;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use crate::approval::{Approver, DenyAll};
use crate::upstream_auth::{TokenCache, UpstreamAuth};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub request_bytes: usize,
    pub result_bytes: usize,
    pub json_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { request_bytes: 64 * 1024, result_bytes: 256 * 1024, json_depth: 32 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SinkErrorMode {
    /// Any audit failure denies the action.
    #[default]
    DenyAll,
    /// Audit failures deny only write actions.
    DenyWrites,
}

pub struct Upstream {
    pub name: String,
    pub client: McpClient,
    pub auth: UpstreamAuth,
    /// URI prefixes routed to this upstream for `resources/read` (e.g. `docs://`).
    pub resource_prefixes: Vec<String>,
}

pub enum KillSource {
    File(PathBuf),
    Memory(Mutex<KillSwitch>),
}

pub struct Inner {
    pub(crate) engine: RwLock<Arc<Engine>>,
    pub(crate) verifier: Arc<Verifier>,
    pub(crate) resolver: Option<Arc<dyn AttributeResolver>>,
    pub(crate) upstreams: BTreeMap<String, Upstream>,
    pub(crate) http: reqwest::Client,
    pub(crate) token_cache: TokenCache,
    pub(crate) sessions: Mutex<HashMap<String, String>>,
    pub(crate) approver: Arc<dyn Approver>,
    pub(crate) approval_timeout: Duration,
    pub(crate) progress_interval: Duration,
    pub(crate) audit: Arc<dyn AuditSink>,
    pub(crate) on_sink_error: SinkErrorMode,
    pub(crate) hmac_key: Vec<u8>,
    pub(crate) kill: KillSource,
    pub(crate) limits: Limits,
    pub(crate) defs: tokio::sync::Mutex<HashMap<String, (Instant, Vec<Value>)>>,
    pub(crate) definition_ttl: Duration,
    pub(crate) list_changed: broadcast::Sender<()>,
    pub(crate) public_url: String,
    pub(crate) admin_token: Option<String>,
}

/// A running gateway (cheap to clone).
#[derive(Clone)]
pub struct Gateway {
    pub(crate) inner: Arc<Inner>,
}

impl std::ops::Deref for Gateway {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.inner
    }
}

pub struct GatewayBuilder {
    engine: Option<Engine>,
    verifier: Option<Verifier>,
    resolver: Option<Arc<dyn AttributeResolver>>,
    upstreams: BTreeMap<String, Upstream>,
    approver: Arc<dyn Approver>,
    approval_timeout: Duration,
    progress_interval: Duration,
    audit: Option<Arc<dyn AuditSink>>,
    on_sink_error: SinkErrorMode,
    hmac_key: Vec<u8>,
    kill: KillSource,
    limits: Limits,
    definition_ttl: Duration,
    public_url: String,
    admin_token: Option<String>,
}

impl Default for GatewayBuilder {
    fn default() -> Self {
        Self {
            engine: None,
            verifier: None,
            resolver: None,
            upstreams: BTreeMap::new(),
            approver: Arc::new(DenyAll),
            approval_timeout: Duration::from_secs(120),
            progress_interval: Duration::from_secs(10),
            audit: None,
            on_sink_error: SinkErrorMode::DenyAll,
            hmac_key: rand::random::<[u8; 32]>().to_vec(),
            kill: KillSource::Memory(Mutex::new(KillSwitch::Off)),
            limits: Limits::default(),
            definition_ttl: Duration::from_secs(5),
            public_url: "http://127.0.0.1:8088/mcp".into(),
            admin_token: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway configuration: {0}")]
    Config(String),
}

impl GatewayBuilder {
    pub fn engine(mut self, e: Engine) -> Self {
        self.engine = Some(e);
        self
    }
    pub fn verifier(mut self, v: Verifier) -> Self {
        self.verifier = Some(v);
        self
    }
    pub fn resolver(mut self, r: Arc<dyn AttributeResolver>) -> Self {
        self.resolver = Some(r);
        self
    }
    pub fn upstream(mut self, name: &str, url: &str, auth: UpstreamAuth, resource_prefixes: Vec<String>) -> Self {
        self.upstreams.insert(name.to_string(), Upstream { name: name.to_string(), client: McpClient::new(url), auth, resource_prefixes });
        self
    }
    pub fn approver(mut self, a: Arc<dyn Approver>) -> Self {
        self.approver = a;
        self
    }
    pub fn approval_timeout(mut self, d: Duration) -> Self {
        self.approval_timeout = d;
        self
    }
    pub fn progress_interval(mut self, d: Duration) -> Self {
        self.progress_interval = d;
        self
    }
    pub fn audit(mut self, a: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(a);
        self
    }
    pub fn on_sink_error(mut self, m: SinkErrorMode) -> Self {
        self.on_sink_error = m;
        self
    }
    pub fn hmac_key(mut self, k: Vec<u8>) -> Self {
        self.hmac_key = k;
        self
    }
    pub fn kill_switch_file(mut self, p: PathBuf) -> Self {
        self.kill = KillSource::File(p);
        self
    }
    pub fn limits(mut self, l: Limits) -> Self {
        self.limits = l;
        self
    }
    pub fn definition_ttl(mut self, d: Duration) -> Self {
        self.definition_ttl = d;
        self
    }
    pub fn public_url(mut self, u: impl Into<String>) -> Self {
        self.public_url = u.into();
        self
    }
    pub fn admin_token(mut self, t: Option<String>) -> Self {
        self.admin_token = t;
        self
    }

    pub fn build(self) -> Result<Gateway, GatewayError> {
        let engine = self.engine.ok_or_else(|| GatewayError::Config("engine missing".into()))?;
        let verifier = self.verifier.ok_or_else(|| GatewayError::Config("verifier missing".into()))?;
        let audit = self.audit.ok_or_else(|| GatewayError::Config("audit sink missing".into()))?;
        let (tx, _) = broadcast::channel(16);
        Ok(Gateway {
            inner: Arc::new(Inner {
                engine: RwLock::new(Arc::new(engine)),
                verifier: Arc::new(verifier),
                resolver: self.resolver,
                upstreams: self.upstreams,
                http: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap_or_default(),
                token_cache: TokenCache::default(),
                sessions: Mutex::new(HashMap::new()),
                approver: self.approver,
                approval_timeout: self.approval_timeout,
                progress_interval: self.progress_interval,
                audit,
                on_sink_error: self.on_sink_error,
                hmac_key: self.hmac_key,
                kill: self.kill,
                limits: self.limits,
                defs: tokio::sync::Mutex::new(HashMap::new()),
                definition_ttl: self.definition_ttl,
                list_changed: tx,
                public_url: self.public_url,
                admin_token: self.admin_token,
            }),
        })
    }
}

impl Gateway {
    pub fn builder() -> GatewayBuilder {
        GatewayBuilder::default()
    }

    /// The current engine (hot-reload swaps it atomically).
    pub fn engine(&self) -> Arc<Engine> {
        self.inner.engine.read().map(|e| e.clone()).unwrap_or_else(|p| p.into_inner().clone())
    }

    pub fn swap_engine(&self, e: Engine) {
        match self.inner.engine.write() {
            Ok(mut g) => *g = Arc::new(e),
            Err(p) => *p.into_inner() = Arc::new(e),
        }
        let _ = self.inner.list_changed.send(());
    }

    pub fn kill_switch(&self) -> KillSwitch {
        match &self.inner.kill {
            KillSource::Memory(m) => m.lock().map(|k| *k).unwrap_or(KillSwitch::All),
            KillSource::File(p) => match std::fs::read_to_string(p) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => KillSwitch::Off,
                Err(_) => KillSwitch::All,
                Ok(s) => match s.trim() {
                    "" | "off" => KillSwitch::Off,
                    "writes" => KillSwitch::Writes,
                    // Unknown content fails closed.
                    _ => KillSwitch::All,
                },
            },
        }
    }

    pub fn set_kill_switch(&self, k: KillSwitch) -> std::io::Result<()> {
        match &self.inner.kill {
            KillSource::Memory(m) => {
                if let Ok(mut g) = m.lock() {
                    *g = k;
                }
                Ok(())
            }
            KillSource::File(p) => match k {
                KillSwitch::Off => match std::fs::remove_file(p) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    r => r,
                },
                KillSwitch::Writes => std::fs::write(p, "writes"),
                KillSwitch::All => std::fs::write(p, "all"),
            },
        }
    }

    /// Context values come from the gateway, never from the model.
    pub fn context(&self) -> Context {
        let now = chrono::Utc::now();
        let mut values = agent_scope_core::Attrs::new();
        values.insert("hour_utc".into(), AttrValue::Number(now.hour() as f64));
        values.insert("weekday".into(), AttrValue::String(now.format("%a").to_string().to_lowercase()));
        values.insert("transport".into(), AttrValue::String("http".into()));
        Context { kill_switch: self.kill_switch(), values }
    }

    pub(crate) fn principal_fields(p: &Principal) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("subject".into(), json!(p.subject.id));
        m.insert("agent".into(), json!(p.agent));
        m.insert("act".into(), json!(p.act));
        m
    }

    /// Record an event. Returns false if the sink failed (caller decides whether to deny).
    pub(crate) fn record(&self, event: &str, fields: Value) -> bool {
        match self.inner.audit.record(event, fields) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(error = %e, event, "audit sink failed");
                false
            }
        }
    }

    /// Audit a decision. If the sink fails, the decision is turned into a deny
    /// (for writes only, with `SinkErrorMode::DenyWrites`).
    pub(crate) fn audit_decision(&self, p: &Principal, a: &Action, d: Decision) -> Decision {
        let engine = self.engine();
        let resolved = engine.catalog().resolve(&a.kind, &a.name);
        let clear = resolved.as_ref().is_some_and(|r| r.audit_args);
        let mut f = Self::principal_fields(p);
        f.insert("effect".into(), json!(d.effect));
        f.insert("rule".into(), json!(d.rule));
        f.insert("reason".into(), json!(d.reason));
        f.insert("policy_version".into(), json!(d.policy_version));
        let mut action = json!({"kind": a.kind.as_str(), "name": a.name, "args_hmac": args_hmac(&self.hmac_key, &a.args)});
        if clear {
            action["args"] = a.args.clone();
        }
        f.insert("action".into(), action);
        if self.record("decision", Value::Object(f)) || d.effect == agent_scope_core::Effect::Deny {
            return d;
        }
        let is_write = resolved.is_some_and(|r| r.sensitivity == Sensitivity::Write);
        if self.inner.on_sink_error == SinkErrorMode::DenyWrites && !is_write {
            return d;
        }
        let mut denied = d;
        denied.effect = agent_scope_core::Effect::Deny;
        denied.rule = "audit.unavailable".into();
        denied.reason = "audit sink failed; failing closed".into();
        denied.model_message = "This action is not permitted.".into();
        denied
    }

    pub fn subscribe_list_changed(&self) -> broadcast::Receiver<()> {
        self.inner.list_changed.subscribe()
    }

    /// Upstream definitions (tools or prompts) with a short cache.
    pub(crate) async fn definitions(&self, up: &Upstream, cred: Option<&str>, force: bool) -> Result<Vec<Value>, String> {
        let key = format!("{}#tools", up.name);
        if !force {
            if let Some((at, defs)) = self.inner.defs.lock().await.get(&key) {
                if at.elapsed() < self.inner.definition_ttl {
                    return Ok(defs.clone());
                }
            }
        }
        let defs = up.client.list_all(cred, "tools/list", "tools").await.map_err(|e| e.to_string())?;
        self.inner.defs.lock().await.insert(key, (Instant::now(), defs.clone()));
        Ok(defs)
    }
}
