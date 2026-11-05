#![cfg(feature = "otlp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! OTLP export against a mock collector.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use warden_audit::otlp::{OtlpConfig, OtlpSink};
use warden_audit::AuditSink;

#[tokio::test]
async fn decisions_arrive_as_otlp_log_records() {
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let r2 = received.clone();
    let app = Router::new().route(
        "/v1/logs",
        post(move |Json(v): Json<Value>| {
            let r = r2.clone();
            async move {
                r.lock().unwrap().push(v);
                Json(json!({}))
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

    let mut cfg = OtlpConfig::new(url);
    cfg.flush_interval = Duration::from_millis(50);
    cfg.service_name = "gw-test".into();
    let sink = OtlpSink::spawn(cfg);
    sink.record(
        "decision",
        json!({"effect": "deny", "rule": "own-orgs-only", "subject": "dana", "agent": "coding-agent", "act": [],
               "action": {"kind": "tool", "name": "github.create_issue"}}),
    )
    .unwrap();
    sink.record("upstream_down", json!({"upstream": "github"})).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let bodies = received.lock().unwrap().clone();
    let records: Vec<Value> =
        bodies.iter().flat_map(|b| b["resourceLogs"][0]["scopeLogs"][0]["logRecords"].as_array().cloned().unwrap_or_default()).collect();
    assert_eq!(records.len(), 2, "{bodies:#?}");
    assert_eq!(bodies[0]["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"], "gw-test");
    let attr = |r: &Value, k: &str| r["attributes"].as_array().unwrap().iter().find(|a| a["key"] == k).map(|a| a["value"].clone());
    let d = &records[0];
    assert_eq!(d["severityText"], "WARN");
    assert_eq!(attr(d, "warden.effect"), Some(json!({"stringValue": "deny"})));
    assert_eq!(attr(d, "warden.rule"), Some(json!({"stringValue": "own-orgs-only"})));
    assert_eq!(attr(d, "warden.action.name"), Some(json!({"stringValue": "github.create_issue"})));
    assert_eq!(attr(d, "event.name"), Some(json!({"stringValue": "warden.decision"})));
    assert_eq!(sink.dropped(), 0);
}

#[tokio::test]
async fn an_unreachable_collector_never_fails_a_decision() {
    let mut cfg = OtlpConfig::new("http://127.0.0.1:1");
    cfg.flush_interval = Duration::from_millis(20);
    let sink = OtlpSink::spawn(cfg);
    for _ in 0..3 {
        assert!(sink.record("decision", json!({"effect": "allow"})).is_ok());
    }
    // A refused connection takes ~2 s on Windows, milliseconds elsewhere.
    for _ in 0..50 {
        if sink.dropped() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(sink.dropped() >= 1, "failed deliveries are counted");
}
