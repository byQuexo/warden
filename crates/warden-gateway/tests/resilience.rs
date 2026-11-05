#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Circuit breaker: a failing upstream is skipped after N failures, its tools disappear,
//! calls fail fast, and it comes back on its own after the cooldown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use warden_audit::MemorySink;
use warden_core::{Engine, IdentityConfig};
use warden_gateway::gateway::CircuitConfig;
use warden_gateway::{Gateway, UpstreamAuth};
use warden_identity::{Sts, StsConfig, Verifier};
use warden_mcp::McpClient;
use warden_testkit::{router, serve, Profile};

const POLICY: &str = include_str!("../../../examples/minimal/policy.yaml");
const CATALOG: &str = include_str!("../../../examples/minimal/catalog.yaml");
const ISS: &str = "https://sts.test";
const AUD: &str = "http://gw.test/mcp";

async fn flaky_ticket_server(down: Arc<AtomicBool>) -> String {
    let r = router(Profile::Ticket).layer(middleware::from_fn(move |req: Request, next: Next| {
        let down = down.clone();
        async move {
            if down.load(Ordering::SeqCst) {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let resp: Response = next.run(req).await;
            resp
        }
    }));
    format!("{}/mcp", serve(r).await)
}

async fn names(c: &McpClient, token: &str) -> Vec<String> {
    let r = c.call(Some(token), "tools/list", json!({})).await.unwrap().result.unwrap();
    let mut v: Vec<String> = r["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn failing_upstream_is_skipped_and_recovers() {
    let sts = Sts::new(StsConfig { issuer: ISS.into(), token_ttl_s: 300, clients: HashMap::new() }, None).unwrap();
    let identity = IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - {{ issuer: {ISS}, audience: {AUD}, algorithms: [ES256], mapping: {{ preset: keycloak }} }}\nscope_claim: ignore\n"
    ))
    .unwrap();
    let down = Arc::new(AtomicBool::new(false));
    let url = flaky_ticket_server(down.clone()).await;
    let audit = MemorySink::new();
    let gw = Gateway::builder()
        .engine(Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap())
        .verifier(Verifier::new(identity).with_static_jwks(ISS, sts.jwks()))
        .public_url(AUD)
        .upstream("ticket", &url, UpstreamAuth::None, vec![])
        .audit(audit.clone())
        .definition_ttl(Duration::ZERO)
        .circuit(CircuitConfig { open_after: 2, cooldown: Duration::from_millis(400) })
        .build()
        .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_url = format!("http://{}/mcp", l.local_addr().unwrap());
    tokio::spawn(gw.clone().serve(l, None));

    let sam = sts.user_token("sam", "helpdesk-bot", &["support"], json!({}), AUD, &[], 300).unwrap();
    let c = McpClient::new(gw_url);
    assert_eq!(names(&c, &sam).await, vec!["ticket.close", "ticket.list"]);

    // The server goes down: two failed listings open the circuit.
    down.store(true, Ordering::SeqCst);
    assert!(names(&c, &sam).await.is_empty());
    assert!(names(&c, &sam).await.is_empty());
    assert_eq!(audit.events_of("upstream_down").len(), 1);
    let errors = audit.events_of("upstream_error").len();

    // While open, the upstream is not contacted at all and calls fail fast.
    assert!(names(&c, &sam).await.is_empty());
    assert_eq!(audit.events_of("upstream_error").len(), errors, "open circuit must not hit the upstream");
    let r = c.call(Some(&sam), "tools/call", json!({"name": "ticket.list", "arguments": {}})).await.unwrap().result;
    assert!(r.is_err() || r.as_ref().is_ok_and(|v: &Value| v["isError"] == true), "{r:?}");
    assert_eq!(gw.upstream_health()[0].state, "open");

    // It recovers after the cooldown (half-open probe succeeds).
    down.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert_eq!(names(&c, &sam).await, vec!["ticket.close", "ticket.list"]);
    assert_eq!(audit.events_of("upstream_up").len(), 1);
    assert_eq!(gw.upstream_health()[0].state, "closed");
}
