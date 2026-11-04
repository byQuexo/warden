#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End to end: STS-issued tokens → A2A proxy → mock A2A agent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use warden_a2a::{A2aProxy, A2aProxyConfig, CARD_PATH};
use warden_audit::MemorySink;
use warden_core::{Engine, IdentityConfig};
use warden_identity::{ClientDef, Sts, StsConfig, Verifier};

const POLICY: &str = include_str!("../../../examples/acme/policy.yaml");
const CATALOG: &str = include_str!("../../../examples/acme/catalog.yaml");

struct Env {
    sts: Arc<Sts>,
    proxy_url: String,
    upstream_calls: Arc<Mutex<Vec<Value>>>,
    audit: Arc<MemorySink>,
}

async fn env() -> Env {
    let sts_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sts_url = format!("http://{}", sts_l.local_addr().unwrap());
    let sts = Arc::new(
        Sts::new(
            StsConfig { issuer: sts_url.clone(), token_ttl_s: 300, clients: HashMap::from([("x".into(), ClientDef::default())]) },
            None,
        )
        .unwrap(),
    );
    let r = sts.clone().router();
    tokio::spawn(async move { axum::serve(sts_l, r).await.unwrap() });

    // A minimal A2A agent: card with two skills, message/send creates a task.
    let calls = Arc::new(Mutex::new(Vec::new()));
    let c2 = calls.clone();
    let upstream = Router::new()
        .route(
            CARD_PATH,
            get(|| async {
                Json(json!({
                    "name": "Acme research agent", "url": "http://internal", "version": "1.0",
                    "skills": [
                        {"id": "deep_search", "name": "Deep search", "tags": ["research"]},
                        {"id": "hr_lookup", "name": "HR lookup", "tags": ["hr"]}
                    ]
                }))
            }),
        )
        .route(
            "/",
            post(move |headers: axum::http::HeaderMap, Json(m): Json<Value>| {
                let c = c2.clone();
                async move {
                    c.lock().unwrap().push(json!({"msg": m, "auth": headers.get("authorization").and_then(|v| v.to_str().ok())}));
                    let id = m["id"].clone();
                    match m["method"].as_str() {
                        Some("message/send") => Json(json!({"jsonrpc": "2.0", "id": id, "result": {"kind": "task", "id": "task-1", "status": {"state": "submitted"}}})),
                        _ => Json(json!({"jsonrpc": "2.0", "id": id, "result": {"kind": "task", "id": "task-1", "status": {"state": "completed"}}})),
                    }
                }
            }),
        );
    let up_url = warden_testkit::serve(upstream).await;

    let proxy_l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy_l.local_addr().unwrap());
    let identity = IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - issuer: {sts_url}\n    audience: {proxy_url}\n    algorithms: [ES256]\n    mapping: {{ preset: keycloak, attrs: {{ tenants: /tenants }} }}\ndelegation_issuers: [{sts_url}]\nscope_claim: ignore\n"
    ))
    .unwrap();
    let engine = Arc::new(Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap());
    let audit = MemorySink::new();
    let proxy = A2aProxy::new(
        A2aProxyConfig {
            upstream_url: up_url,
            upstream_card_url: None,
            public_url: proxy_url.clone(),
            skill_prefix: "research.".into(),
            upstream_token: Some("proxy-service-token".into()),
        },
        engine,
        Arc::new(Verifier::new(identity)),
        audit.clone(),
        b"k".to_vec(),
    );
    let router = proxy.router();
    tokio::spawn(async move { axum::serve(proxy_l, router).await.unwrap() });
    Env { sts, proxy_url, upstream_calls: calls, audit }
}

impl Env {
    fn token(&self, user: &str, roles: &[&str], agent: &str) -> String {
        self.sts.user_token(user, agent, roles, json!({}), &self.proxy_url, &[], 300).unwrap()
    }
    async fn card(&self, token: Option<&str>) -> Value {
        let mut r = reqwest::Client::new().get(format!("{}{CARD_PATH}", self.proxy_url));
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        r.send().await.unwrap().json().await.unwrap()
    }
    async fn rpc(&self, token: &str, body: Value) -> Value {
        reqwest::Client::new()
            .post(format!("{}/", self.proxy_url))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

fn send(skill: Option<&str>) -> Value {
    let mut meta = json!({});
    if let Some(s) = skill {
        meta["skillId"] = json!(s);
    }
    json!({"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {
        "message": {"role": "user", "messageId": "m-1", "parts": [{"kind": "text", "text": "pipeline for Q4"}]},
        "metadata": meta
    }})
}

#[tokio::test]
async fn agent_card_lists_only_permitted_skills() {
    let e = env().await;
    let sara = e.token("sara", &["sales-lead"], "acme-research");
    let card = e.card(Some(&sara)).await;
    let ids: Vec<&str> = card["skills"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["deep_search"], "hr_lookup is not in the catalog, so it is never shown");
    assert_eq!(card["url"], e.proxy_url);
    // Anonymous callers and callers without the scope see no skills.
    assert!(e.card(None).await["skills"].as_array().unwrap().is_empty());
    let sven = e.token("sven", &["sales-rep"], "acme-research");
    assert!(e.card(Some(&sven)).await["skills"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn messages_are_enforced_per_skill_and_tasks_per_owner() {
    let e = env().await;
    let sara = e.token("sara", &["sales-lead"], "acme-research");
    let ok = e.rpc(&sara, send(Some("deep_search"))).await;
    assert_eq!(ok["result"]["id"], "task-1", "{ok}");

    // Upstream saw the proxy's credential, never the caller's token.
    let calls = e.upstream_calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["auth"], "Bearer proxy-service-token");

    for (who, body) in [
        (e.token("sven", &["sales-rep"], "acme-research"), send(Some("deep_search"))), // no research scope
        (sara.clone(), send(Some("hr_lookup"))),                                       // not in catalog
        (sara.clone(), send(None)),                                                    // skill not named
        (e.token("sara", &["sales-lead"], "acme-bot"), send(Some("deep_search"))),     // agent ceiling
    ] {
        let r = e.rpc(&who, body).await;
        assert_eq!(r["error"]["code"], -32001, "{r}");
    }
    assert_eq!(e.upstream_calls.lock().unwrap().len(), 1, "denied calls never reach the agent");

    // Task access is bound to the creator.
    let get = json!({"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": {"id": "task-1"}});
    assert_eq!(e.rpc(&sara, get.clone()).await["result"]["status"]["state"], "completed");
    let other = e.token("sara", &["sales-lead"], "acme-bot");
    assert_eq!(e.rpc(&other, get).await["error"]["code"], -32001, "same user, different agent: different principal");

    let rules: Vec<String> = e.audit.events_of("decision").iter().map(|d| d["rule"].as_str().unwrap().to_string()).collect();
    assert!(rules.contains(&"a2a.task_owner".to_string()));
    assert!(rules.contains(&"scope.missing".to_string()));
}

#[tokio::test]
async fn invalid_tokens_and_duplicate_keys_are_rejected() {
    let e = env().await;
    let r = reqwest::Client::new()
        .post(format!("{}/", e.proxy_url))
        .bearer_auth("garbage")
        .json(&send(Some("deep_search")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let sara = e.token("sara", &["sales-lead"], "acme-research");
    let dup = r#"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"metadata":{"skillId":"deep_search","skillId":"hr_lookup"}}}"#;
    let r = reqwest::Client::new()
        .post(format!("{}/", e.proxy_url))
        .bearer_auth(&sara)
        .header("content-type", "application/json")
        .body(dup)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}
