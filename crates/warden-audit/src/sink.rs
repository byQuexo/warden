use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit configuration error: {0}")]
    Config(String),
    #[error("audit sink unavailable: {0}")]
    Unavailable(String),
}

/// Where audit events go. If `record` fails, the caller must deny the action:
/// an action without an audit record does not happen.
pub trait AuditSink: Send + Sync {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError>;
    /// Force a signed checkpoint (e.g. on shutdown). No-op for sinks without chaining.
    fn checkpoint(&self) -> Result<(), AuditError> {
        Ok(())
    }
    /// The last `n` events, newest last (for the admin API). Optional.
    fn tail(&self, _n: usize) -> Vec<Value> {
        Vec::new()
    }
}

/// `hmac-sha256:<hex>` over the canonical JSON of `v`.
pub fn args_hmac(key: &[u8], v: &Value) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| {
        // HMAC accepts keys of any length; this branch is unreachable but must not panic.
        <Hmac<Sha256> as Mac>::new_from_slice(b"warden").unwrap_or_else(|_| unreachable_mac())
    });
    mac.update(v.to_string().as_bytes());
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

#[allow(clippy::panic)]
fn unreachable_mac() -> Hmac<Sha256> {
    panic!("HMAC rejected a key")
}

pub(crate) fn chain_hash(obj_without_hash: &Value) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(obj_without_hash.to_string().as_bytes())))
}

pub struct JsonlConfig {
    pub dir: PathBuf,
    /// Chain id, usually the instance name. One chain per writer process.
    pub chain: String,
    pub signing_key: Option<SigningKey>,
    /// Write a signed checkpoint after this many events.
    pub checkpoint_every: u64,
}

struct State {
    seq: u64,
    prev: String,
    since_checkpoint: u64,
    day: String,
    file: Option<File>,
}

/// Hash-chained JSON Lines file sink: `<dir>/<chain>-<YYYY-MM-DD>.jsonl`.
pub struct JsonlSink {
    cfg: JsonlConfig,
    state: Mutex<State>,
}

impl JsonlSink {
    pub fn open(cfg: JsonlConfig) -> Result<Self, AuditError> {
        if cfg.chain.is_empty() || !cfg.chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(AuditError::Config("chain id must be [A-Za-z0-9_-]+".into()));
        }
        fs::create_dir_all(&cfg.dir)?;
        let mut state = State { seq: 0, prev: GENESIS.to_string(), since_checkpoint: 0, day: String::new(), file: None };
        // Resume an existing chain.
        let mut files: Vec<PathBuf> = fs::read_dir(&cfg.dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| crate::verify::chain_of(p).as_deref() == Some(cfg.chain.as_str()))
            .collect();
        files.sort();
        if let Some(last) = files.last() {
            for line in BufReader::new(File::open(last)?).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let v: Value = serde_json::from_str(&line)
                    .map_err(|e| AuditError::Config(format!("cannot resume chain from {}: {e}", last.display())))?;
                state.seq = v.get("seq").and_then(Value::as_u64).unwrap_or(state.seq);
                state.prev = v.get("hash").and_then(Value::as_str).unwrap_or(&state.prev).to_string();
                if v.get("event").and_then(Value::as_str) == Some("checkpoint") {
                    state.since_checkpoint = 0;
                } else {
                    state.since_checkpoint += 1;
                }
            }
        }
        Ok(Self { cfg, state: Mutex::new(state) })
    }

    fn write_locked(&self, st: &mut State, event: &str, fields: Value) -> Result<(), AuditError> {
        let now = chrono::Utc::now();
        let day = now.format("%Y-%m-%d").to_string();
        if st.file.is_none() || st.day != day {
            let path = self.cfg.dir.join(format!("{}-{day}.jsonl", self.cfg.chain));
            st.file = Some(OpenOptions::new().create(true).append(true).open(path)?);
            st.day = day;
        }
        let mut obj = Map::new();
        obj.insert("v".into(), Value::from(1));
        obj.insert("ts".into(), Value::from(now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
        obj.insert("chain".into(), Value::from(self.cfg.chain.clone()));
        obj.insert("seq".into(), Value::from(st.seq + 1));
        obj.insert("event".into(), Value::from(event));
        if let Value::Object(f) = fields {
            for (k, v) in f {
                if !matches!(k.as_str(), "v" | "ts" | "chain" | "seq" | "event" | "prev" | "hash") {
                    obj.insert(k, v);
                }
            }
        }
        obj.insert("prev".into(), Value::from(st.prev.clone()));
        let hash = chain_hash(&Value::Object(obj.clone()));
        obj.insert("hash".into(), Value::from(hash.clone()));
        let line = format!("{}\n", Value::Object(obj));
        let file = st.file.as_mut().ok_or_else(|| AuditError::Unavailable("file not open".into()))?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        st.seq += 1;
        st.prev = hash;
        Ok(())
    }

    fn checkpoint_locked(&self, st: &mut State) -> Result<(), AuditError> {
        let Some(key) = &self.cfg.signing_key else {
            return Ok(());
        };
        let head = st.prev.clone();
        let sig = base64::engine::general_purpose::STANDARD.encode(key.sign(head.as_bytes()).to_bytes());
        let key_id = hex::encode(&key.verifying_key().to_bytes()[..8]);
        let fields = serde_json::json!({"head": head, "upto_seq": st.seq, "sig": sig, "key_id": key_id});
        self.write_locked(st, "checkpoint", fields)?;
        st.since_checkpoint = 0;
        Ok(())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>, AuditError> {
        self.state.lock().map_err(|_| AuditError::Unavailable("audit state poisoned".into()))
    }
}

impl AuditSink for JsonlSink {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError> {
        let mut st = self.lock()?;
        self.write_locked(&mut st, event, fields)?;
        st.since_checkpoint += 1;
        if st.since_checkpoint >= self.cfg.checkpoint_every.max(1) {
            self.checkpoint_locked(&mut st)?;
        }
        Ok(())
    }

    fn checkpoint(&self) -> Result<(), AuditError> {
        let mut st = self.lock()?;
        if st.since_checkpoint > 0 {
            self.checkpoint_locked(&mut st)?;
        }
        Ok(())
    }

    fn tail(&self, n: usize) -> Vec<Value> {
        let Ok(st) = self.lock() else { return Vec::new() };
        let path = self.cfg.dir.join(format!("{}-{}.jsonl", self.cfg.chain, st.day));
        drop(st);
        let Ok(text) = fs::read_to_string(path) else { return Vec::new() };
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        lines[lines.len().saturating_sub(n)..].iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

/// In-memory sink for tests; can be switched to fail to exercise fail-closed paths.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<Value>>,
    fail: AtomicBool,
}

impl MemorySink {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn set_failing(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }
    pub fn events(&self) -> Vec<Value> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
    pub fn events_of(&self, kind: &str) -> Vec<Value> {
        self.events().into_iter().filter(|e| e.get("event").and_then(Value::as_str) == Some(kind)).collect()
    }
}

impl AuditSink for MemorySink {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(AuditError::Unavailable("memory sink set to fail".into()));
        }
        let mut obj = match fields {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        obj.insert("event".into(), Value::from(event));
        self.events.lock().map_err(|_| AuditError::Unavailable("poisoned".into()))?.push(Value::Object(obj));
        Ok(())
    }
    fn tail(&self, n: usize) -> Vec<Value> {
        let e = self.events();
        e[e.len().saturating_sub(n)..].to_vec()
    }
}

/// Writes one JSON object per line to stdout.
pub struct StdoutSink;

impl AuditSink for StdoutSink {
    fn record(&self, event: &str, mut fields: Value) -> Result<(), AuditError> {
        if let Value::Object(m) = &mut fields {
            m.insert("event".into(), Value::from(event));
        }
        let mut out = std::io::stdout().lock();
        writeln!(out, "{fields}")?;
        Ok(())
    }
}

/// Emits `tracing` events with `warden.*` fields, so any tracing/OpenTelemetry
/// subscriber (e.g. `tracing-opentelemetry` → Phoenix, Jaeger) receives decisions as spans/events.
pub struct TracingSink;

impl AuditSink for TracingSink {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError> {
        let get = |k: &str| fields.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let (kind, effect, rule) = (event.to_string(), get("effect"), get("rule"));
        let (subject, agent, version) = (get("subject"), get("agent"), get("policy_version"));
        tracing::info!(
            target: "warden::audit",
            audit_event = %kind,
            effect = %effect,
            rule = %rule,
            subject = %subject,
            agent = %agent,
            policy_version = %version,
            payload = %fields,
        );
        Ok(())
    }
}

/// Fan-out to several sinks; fails if any sink fails.
pub struct MultiSink(pub Vec<Arc<dyn AuditSink>>);

impl AuditSink for MultiSink {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError> {
        let mut err = None;
        for s in &self.0 {
            if let Err(e) = s.record(event, fields.clone()) {
                err = Some(e);
            }
        }
        err.map_or(Ok(()), Err)
    }
    fn checkpoint(&self) -> Result<(), AuditError> {
        for s in &self.0 {
            s.checkpoint()?;
        }
        Ok(())
    }
    fn tail(&self, n: usize) -> Vec<Value> {
        self.0.iter().map(|s| s.tail(n)).find(|t| !t.is_empty()).unwrap_or_default()
    }
}
