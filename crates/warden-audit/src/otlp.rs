//! OpenTelemetry export: audit events become OTLP log records (`POST {endpoint}/v1/logs`,
//! OTLP/HTTP JSON), so any collector (OpenTelemetry Collector, Phoenix, Jaeger, Grafana,
//! Datadog, …) can show and alert on Warden decisions.
//!
//! The sink is **best effort** on purpose: events are queued and sent in batches by a
//! background task; a full queue or an unreachable collector drops events (counted in
//! [`OtlpSink::dropped`]) but never blocks or denies a decision. Use the hash-chained
//! [`crate::JsonlSink`] as the audit log of record next to it.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tokio::sync::mpsc;

use crate::{AuditError, AuditSink};

#[derive(Clone, Debug)]
pub struct OtlpConfig {
    /// Collector base URL, e.g. `http://localhost:4318`; `/v1/logs` is appended.
    pub endpoint: String,
    pub service_name: String,
    /// Extra HTTP headers (e.g. an API key for a hosted collector).
    pub headers: Vec<(String, String)>,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub queue: usize,
}

impl OtlpConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            service_name: "warden-gateway".into(),
            headers: vec![],
            batch_size: 256,
            flush_interval: Duration::from_secs(1),
            queue: 10_000,
        }
    }
}

pub struct OtlpSink {
    tx: mpsc::Sender<Value>,
    dropped: Arc<AtomicU64>,
}

impl OtlpSink {
    /// Start the exporter task. Must be called inside a Tokio runtime.
    pub fn spawn(cfg: OtlpConfig) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<Value>(cfg.queue.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let failed = dropped.clone();
        tokio::spawn(async move {
            let http = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default();
            let url = format!("{}/v1/logs", cfg.endpoint.trim_end_matches('/'));
            let mut batch: Vec<Value> = Vec::new();
            let mut tick = tokio::time::interval(cfg.flush_interval);
            loop {
                let closed = tokio::select! {
                    ev = rx.recv() => match ev {
                        Some(e) => { batch.push(e); false }
                        None => true,
                    },
                    _ = tick.tick() => false,
                };
                let full = batch.len() >= cfg.batch_size;
                if !batch.is_empty() && (full || closed || rx.is_empty()) {
                    let records: Vec<Value> = batch.drain(..).map(log_record).collect();
                    let n = records.len() as u64;
                    let body = envelope(&cfg.service_name, records);
                    let mut req = http.post(&url).json(&body);
                    for (k, v) in &cfg.headers {
                        req = req.header(k, v);
                    }
                    match req.send().await {
                        Ok(r) if r.status().is_success() => {}
                        _ => {
                            failed.fetch_add(n, Ordering::Relaxed);
                        }
                    }
                }
                if closed {
                    break;
                }
            }
        });
        Arc::new(Self { tx, dropped })
    }

    /// Events that could not be queued or delivered.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl AuditSink for OtlpSink {
    fn record(&self, event: &str, fields: Value) -> Result<(), AuditError> {
        let mut obj = match fields {
            Value::Object(m) => m,
            _ => Map::new(),
        };
        obj.insert("event".into(), json!(event));
        obj.insert("_time_unix_nano".into(), json!(now_nanos().to_string()));
        if self.tx.try_send(Value::Object(obj)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}

fn attr_value(v: &Value) -> Value {
    match v {
        Value::String(s) => json!({"stringValue": s}),
        Value::Bool(b) => json!({"boolValue": b}),
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({"intValue": n.to_string()}),
        Value::Number(n) => json!({"doubleValue": n.as_f64()}),
        Value::Array(a) => json!({"arrayValue": {"values": a.iter().map(attr_value).collect::<Vec<_>>()}}),
        other => json!({"stringValue": other.to_string()}),
    }
}

/// Flatten fields into `warden.*` attributes (`action.name` → `warden.action.name`).
fn attributes(prefix: &str, m: &Map<String, Value>, out: &mut Vec<Value>) {
    for (k, v) in m {
        if k.starts_with('_') {
            continue;
        }
        let key = format!("{prefix}.{k}");
        match v {
            Value::Object(inner) => attributes(&key, inner, out),
            Value::Null => {}
            other => out.push(json!({"key": key, "value": attr_value(other)})),
        }
    }
}

fn log_record(ev: Value) -> Value {
    let Value::Object(m) = ev else { return json!({}) };
    let time = m.get("_time_unix_nano").cloned().unwrap_or_else(|| json!(now_nanos().to_string()));
    let event = m.get("event").and_then(Value::as_str).unwrap_or("event").to_string();
    let deny = m.get("effect").and_then(Value::as_str) == Some("deny");
    let mut attrs = vec![json!({"key": "event.name", "value": {"stringValue": format!("warden.{event}")}})];
    attributes("warden", &m, &mut attrs);
    json!({
        "timeUnixNano": time,
        "observedTimeUnixNano": time,
        "severityNumber": if deny { 13 } else { 9 },
        "severityText": if deny { "WARN" } else { "INFO" },
        "body": {"stringValue": event},
        "attributes": attrs,
    })
}

fn envelope(service: &str, records: Vec<Value>) -> Value {
    json!({
        "resourceLogs": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]},
            "scopeLogs": [{
                "scope": {"name": "warden.audit", "version": env!("CARGO_PKG_VERSION")},
                "logRecords": records,
            }],
        }]
    })
}
