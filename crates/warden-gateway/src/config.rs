//! `gateway.yaml`: where things run. Paths are relative to the config file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use warden_audit::{signing_key_from_b64, AuditSink, JsonlConfig, JsonlSink, MultiSink, StdoutSink, TracingSink};
use warden_core::{Engine, IdentityConfig};
use warden_identity::{HttpResolver, StaticResolver, Verifier};

use crate::approval::{Approver, AutoApprove, DenyAll, WebhookApprover};
use crate::gateway::{Gateway, GatewayError, Limits, SinkErrorMode};
use crate::upstream_auth::UpstreamAuth;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default)]
    pub admin_listen: Option<String>,
    #[serde(default)]
    pub admin_token_env: Option<String>,
    pub public_url: String,
    pub identity: String,
    pub policy: PolicyFiles,
    #[serde(default)]
    pub attributes: Option<AttributesCfg>,
    #[serde(default)]
    pub limits: LimitsCfg,
    #[serde(default)]
    pub upstreams: BTreeMap<String, UpstreamCfg>,
    #[serde(default)]
    pub approval: ApprovalCfg,
    pub audit: AuditCfg,
    #[serde(default)]
    pub kill_switch: Option<KillCfg>,
    #[serde(default)]
    pub health: Option<HealthCfg>,
}

/// Circuit breaker per upstream.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCfg {
    #[serde(default = "d_open_after")]
    pub open_after_failures: u32,
    #[serde(default = "d_cooldown")]
    pub cooldown_ms: u64,
}
fn d_open_after() -> u32 {
    3
}
fn d_cooldown() -> u64 {
    30_000
}

fn default_listen() -> String {
    "127.0.0.1:8088".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFiles {
    pub catalog: String,
    pub policy: String,
    #[serde(default)]
    pub lock: Option<String>,
    /// Poll interval for hot reload; 0 disables reloading.
    #[serde(default = "default_reload")]
    pub reload_ms: u64,
}

fn default_reload() -> u64 {
    1000
}

#[derive(Debug, Deserialize)]
#[serde(tag = "resolver", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AttributesCfg {
    Static {
        file: String,
    },
    Http {
        url: String,
        #[serde(default = "default_cache")]
        cache_s: u64,
    },
}

fn default_cache() -> u64 {
    60
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    #[serde(default = "d_req")]
    pub request_bytes: usize,
    #[serde(default = "d_res")]
    pub result_bytes: usize,
    #[serde(default = "d_depth")]
    pub json_depth: usize,
}
fn d_req() -> usize {
    65536
}
fn d_res() -> usize {
    262144
}
fn d_depth() -> usize {
    32
}
impl Default for LimitsCfg {
    fn default() -> Self {
        Self { request_bytes: d_req(), result_bytes: d_res(), json_depth: d_depth() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamCfg {
    /// Streamable HTTP endpoint …
    #[serde(default)]
    pub url: Option<String>,
    /// … or a local server started by the gateway and spoken to over stdio.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Environment variables passed through from the gateway to a stdio server.
    #[serde(default)]
    pub pass_env: Vec<String>,
    #[serde(default)]
    pub auth: UpstreamAuthCfg,
    #[serde(default)]
    pub resources: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(tag = "strategy", rename_all = "kebab-case", deny_unknown_fields)]
pub enum UpstreamAuthCfg {
    #[default]
    None,
    Static {
        token_env: String,
    },
    ClientCredentials {
        token_url: String,
        client_id: String,
        secret_env: String,
        #[serde(default)]
        audience: Option<String>,
        #[serde(default)]
        scope: Option<String>,
    },
    TokenExchange {
        token_url: String,
        client_id: String,
        secret_env: String,
        audience: String,
        #[serde(default)]
        scope: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalCfg {
    #[serde(default = "d_approver")]
    pub approver: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub secret_env: Option<String>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_progress")]
    pub progress_interval_ms: u64,
}
fn d_approver() -> String {
    "deny-all".into()
}
fn d_timeout() -> u64 {
    120_000
}
fn d_progress() -> u64 {
    10_000
}
impl Default for ApprovalCfg {
    fn default() -> Self {
        Self { approver: d_approver(), url: None, secret_env: None, timeout_ms: d_timeout(), progress_interval_ms: d_progress() }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCfg {
    pub sinks: Vec<SinkCfg>,
    #[serde(default)]
    pub hmac_key_env: Option<String>,
    #[serde(default = "d_sink_err")]
    pub on_sink_error: String,
}
fn d_sink_err() -> String {
    "deny".into()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SinkCfg {
    Jsonl {
        dir: String,
        #[serde(default = "d_chain")]
        chain: String,
        #[serde(default)]
        checkpoint_key_env: Option<String>,
        #[serde(default = "d_every")]
        checkpoint_every: u64,
    },
    Stdout,
    Tracing,
}
fn d_chain() -> String {
    "gw-1".into()
}
fn d_every() -> u64 {
    1000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillCfg {
    pub file: String,
}

/// Everything loaded from disk, ready to serve.
pub struct Loaded {
    pub gateway: Gateway,
    pub listen: String,
    pub admin_listen: Option<String>,
    pub watch: Vec<PathBuf>,
    pub reload: Option<Duration>,
    pub files: (PathBuf, PathBuf, Option<PathBuf>),
}

fn env(name: &str) -> Result<String, GatewayError> {
    std::env::var(name).map_err(|_| GatewayError::Config(format!("environment variable `{name}` is not set")))
}

fn is_local(url: &str) -> bool {
    let rest = url.strip_prefix("http://").unwrap_or("");
    rest.starts_with("127.0.0.1") || rest.starts_with("localhost") || rest.starts_with("[::1]")
}

/// Build the engine from the three policy files.
pub fn load_engine(catalog: &Path, policy: &Path, lock: Option<&Path>) -> Result<Engine, GatewayError> {
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| GatewayError::Config(format!("{}: {e}", p.display())));
    let mut b = Engine::builder().catalog_yaml(&read(catalog)?).policy_yaml(&read(policy)?);
    if let Some(l) = lock {
        if l.exists() {
            b = b.lock_json(&read(l)?);
        }
    }
    b.build().map_err(|e| GatewayError::Config(e.to_string()))
}

impl GatewayConfig {
    pub fn from_file(path: &Path) -> Result<(Self, PathBuf), GatewayError> {
        let text = std::fs::read_to_string(path).map_err(|e| GatewayError::Config(format!("{}: {e}", path.display())))?;
        let cfg: GatewayConfig = serde_norway::from_str(&text).map_err(|e| GatewayError::Config(format!("{}: {e}", path.display())))?;
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok((cfg, base))
    }

    /// Validate and build. Insecure settings require `dev = true`.
    pub fn load(self, base: &Path, dev: bool) -> Result<Loaded, GatewayError> {
        let rel = |p: &str| base.join(p);
        let identity_text = std::fs::read_to_string(rel(&self.identity)).map_err(|e| GatewayError::Config(format!("identity: {e}")))?;
        let identity = IdentityConfig::from_yaml_str(&identity_text).map_err(|e| GatewayError::Config(format!("identity: {e}")))?;
        if !dev {
            for i in &identity.issuers {
                if i.issuer.starts_with("http://") && !is_local(&i.issuer) {
                    return Err(GatewayError::Config(format!("issuer `{}` uses plain HTTP; use https or run with --dev", i.issuer)));
                }
            }
            if self.approval.approver == "auto-approve" {
                return Err(GatewayError::Config("approver `auto-approve` is only allowed with --dev".into()));
            }
        }
        let (catalog, policy, lock) = (rel(&self.policy.catalog), rel(&self.policy.policy), self.policy.lock.as_deref().map(rel));
        let engine = load_engine(&catalog, &policy, lock.as_deref())?;

        let mut b = Gateway::builder()
            .engine(engine)
            .verifier(Verifier::new(identity))
            .public_url(self.public_url.clone())
            .limits(Limits {
                request_bytes: self.limits.request_bytes,
                result_bytes: self.limits.result_bytes,
                json_depth: self.limits.json_depth,
            })
            .approval_timeout(Duration::from_millis(self.approval.timeout_ms))
            .progress_interval(Duration::from_millis(self.approval.progress_interval_ms));

        if let Some(e) = &self.admin_token_env {
            b = b.admin_token(Some(env(e)?));
        }
        if let Some(h) = &self.health {
            b = b.circuit(crate::gateway::CircuitConfig {
                open_after: h.open_after_failures.max(1),
                cooldown: Duration::from_millis(h.cooldown_ms),
            });
        }
        if let Some(k) = &self.kill_switch {
            b = b.kill_switch_file(rel(&k.file));
        }
        match &self.attributes {
            None => {}
            Some(AttributesCfg::Static { file }) => {
                let t = std::fs::read_to_string(rel(file)).map_err(|e| GatewayError::Config(format!("attributes: {e}")))?;
                b = b.resolver(Arc::new(StaticResolver::from_yaml_str(&t).map_err(GatewayError::Config)?));
            }
            Some(AttributesCfg::Http { url, cache_s }) => {
                b = b.resolver(Arc::new(HttpResolver::new(url.clone(), Duration::from_secs(*cache_s))));
            }
        }
        for (name, u) in &self.upstreams {
            let auth = match &u.auth {
                UpstreamAuthCfg::None => UpstreamAuth::None,
                UpstreamAuthCfg::Static { token_env } => UpstreamAuth::Static(env(token_env)?),
                UpstreamAuthCfg::ClientCredentials { token_url, client_id, secret_env, audience, scope } => {
                    UpstreamAuth::ClientCredentials {
                        token_url: token_url.clone(),
                        client_id: client_id.clone(),
                        secret: env(secret_env)?,
                        audience: audience.clone(),
                        scope: scope.clone(),
                    }
                }
                UpstreamAuthCfg::TokenExchange { token_url, client_id, secret_env, audience, scope } => UpstreamAuth::TokenExchange {
                    token_url: token_url.clone(),
                    client_id: client_id.clone(),
                    secret: env(secret_env)?,
                    audience: audience.clone(),
                    scope: scope.clone(),
                },
            };
            match (&u.url, &u.command) {
                (Some(url), None) => b = b.upstream(name, url, auth, u.resources.clone()),
                (None, Some(cmd)) if !cmd.is_empty() => {
                    if !matches!(u.auth, UpstreamAuthCfg::None) {
                        return Err(GatewayError::Config(format!(
                            "upstream `{name}`: stdio servers take credentials via pass_env, not auth"
                        )));
                    }
                    let env = u.pass_env.iter().map(|k| env(k).map(|v| (k.clone(), v))).collect::<Result<Vec<_>, _>>()?;
                    let spec = warden_mcp::StdioSpec { command: cmd[0].clone(), args: cmd[1..].to_vec(), env };
                    b = b.upstream_stdio(name, spec, u.resources.clone());
                }
                _ => return Err(GatewayError::Config(format!("upstream `{name}` needs exactly one of `url` or `command`"))),
            }
        }
        let approver: Arc<dyn Approver> = match self.approval.approver.as_str() {
            "deny-all" => Arc::new(DenyAll),
            "auto-approve" => Arc::new(AutoApprove),
            "webhook" => {
                let url = self.approval.url.clone().ok_or_else(|| GatewayError::Config("approval.url is required for webhook".into()))?;
                let secret = self.approval.secret_env.as_deref().map(env).transpose()?.map(String::into_bytes);
                Arc::new(WebhookApprover::new(url, secret, Duration::from_millis(self.approval.timeout_ms)))
            }
            other => return Err(GatewayError::Config(format!("unknown approver `{other}`"))),
        };
        b = b.approver(approver);

        let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();
        for s in &self.audit.sinks {
            sinks.push(match s {
                SinkCfg::Stdout => Arc::new(StdoutSink),
                SinkCfg::Tracing => Arc::new(TracingSink),
                SinkCfg::Jsonl { dir, chain, checkpoint_key_env, checkpoint_every } => {
                    let key = checkpoint_key_env
                        .as_deref()
                        .map(env)
                        .transpose()?
                        .map(|k| signing_key_from_b64(&k))
                        .transpose()
                        .map_err(|e| GatewayError::Config(e.to_string()))?;
                    if key.is_none() && !dev {
                        return Err(GatewayError::Config(
                            "jsonl audit sink needs checkpoint_key_env (signed checkpoints) outside --dev".into(),
                        ));
                    }
                    Arc::new(
                        JsonlSink::open(JsonlConfig {
                            dir: rel(dir),
                            chain: chain.clone(),
                            signing_key: key,
                            checkpoint_every: *checkpoint_every,
                        })
                        .map_err(|e| GatewayError::Config(e.to_string()))?,
                    )
                }
            });
        }
        if sinks.is_empty() {
            return Err(GatewayError::Config("at least one audit sink is required".into()));
        }
        b = b.audit(Arc::new(MultiSink(sinks)));
        if let Some(k) = &self.audit.hmac_key_env {
            b = b.hmac_key(env(k)?.into_bytes());
        } else if !dev {
            return Err(GatewayError::Config("audit.hmac_key_env is required outside --dev".into()));
        }
        b = b.on_sink_error(match self.audit.on_sink_error.as_str() {
            "deny" => SinkErrorMode::DenyAll,
            "deny-writes" => SinkErrorMode::DenyWrites,
            o => return Err(GatewayError::Config(format!("unknown on_sink_error `{o}`"))),
        });

        let mut watch = vec![catalog.clone(), policy.clone()];
        if let Some(l) = &lock {
            watch.push(l.clone());
        }
        Ok(Loaded {
            gateway: b.build()?,
            listen: self.listen,
            admin_listen: self.admin_listen,
            watch,
            reload: (self.policy.reload_ms > 0).then(|| Duration::from_millis(self.policy.reload_ms)),
            files: (catalog, policy, lock),
        })
    }
}
