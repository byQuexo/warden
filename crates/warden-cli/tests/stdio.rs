#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! stdio upstreams end to end: the gateway starts local MCP servers as child processes
//! (here `warden dev mock-mcp --stdio`) and enforces policy on them like on HTTP servers.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;
use warden_audit::MemorySink;
use warden_core::{Engine, IdentityConfig};
use warden_gateway::Gateway;
use warden_identity::{Sts, StsConfig, Verifier};
use warden_mcp::{McpClient, StdioSpec};

const ISS: &str = "https://sts.test";
const AUD: &str = "http://gw.test/mcp";

fn spec(profile: &str) -> StdioSpec {
    StdioSpec {
        command: env!("CARGO_BIN_EXE_warden").into(),
        args: ["dev", "mock-mcp", "--profile", profile, "--stdio"].map(String::from).to_vec(),
        env: vec![],
    }
}

#[tokio::test]
async fn gateway_enforces_policy_on_stdio_servers() {
    let catalog = "version: 1\ntool:\n  ticket.list: { scopes: [ticket:read] }\n  ticket.close: { scopes: [ticket:write], sensitivity: write }\n  evil.list_deals: { scopes: [ticket:read] }\n";
    let policy = "version: 1\nroles:\n  viewer: [ticket:read]\n  support: [ticket:read, ticket:write]\nagents:\n  helpdesk-bot: { max: [ticket:read, ticket:write] }\nrules:\n  - { id: ticket-ids-only, match: { kind: tool, name: ticket.close }, require: { arg: id, regex: '^T-[0-9]+$' } }\n";
    let sts = Sts::new(StsConfig { issuer: ISS.into(), token_ttl_s: 300, clients: HashMap::new() }, None).unwrap();
    let identity = IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - {{ issuer: {ISS}, audience: {AUD}, algorithms: [ES256], mapping: {{ preset: keycloak }} }}\nscope_claim: ignore\n"
    ))
    .unwrap();
    let audit = MemorySink::new();
    let gw = Gateway::builder()
        .engine(Engine::builder().policy_yaml(policy).catalog_yaml(catalog).build().unwrap())
        .verifier(Verifier::new(identity).with_static_jwks(ISS, sts.jwks()))
        .public_url(AUD)
        .upstream_stdio("ticket", spec("ticket"), vec![])
        .upstream_stdio("evil", spec("evil"), vec![])
        .audit(audit.clone())
        .definition_ttl(Duration::ZERO)
        .build()
        .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", l.local_addr().unwrap());
    tokio::spawn(gw.clone().serve(l, None));
    let c = McpClient::new(url);

    let vera = sts.user_token("vera", "helpdesk-bot", &["viewer"], json!({}), AUD, &[], 300).unwrap();
    let sam = sts.user_token("sam", "helpdesk-bot", &["support"], json!({}), AUD, &[], 300).unwrap();
    let names = |r: serde_json::Value| {
        let mut v: Vec<String> = r["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        v.sort();
        v
    };

    // Lists are filtered per user; the homoglyph tool of the evil server is rejected.
    let r = c.call(Some(&vera), "tools/list", json!({})).await.unwrap().result.unwrap();
    assert_eq!(names(r), vec!["evil.list_deals", "ticket.list"]);
    let r = c.call(Some(&sam), "tools/list", json!({})).await.unwrap().result.unwrap();
    assert_eq!(names(r), vec!["evil.list_deals", "ticket.close", "ticket.list"]);

    // Calls are enforced, including argument rules.
    let call = |t: &str, name: &str, args: serde_json::Value| {
        let c = &c;
        let t = t.to_string();
        let name = name.to_string();
        async move { c.call(Some(&t), "tools/call", json!({"name": name, "arguments": args})).await.unwrap().result.unwrap() }
    };
    assert_eq!(call(&vera, "ticket.close", json!({"id": "T-1"})).await["isError"], true);
    assert_eq!(call(&sam, "ticket.close", json!({"id": "T-1 OR 1=1"})).await["isError"], true);
    assert_eq!(call(&sam, "ticket.close", json!({"id": "T-42"})).await["structuredContent"]["ok"], true);

    // A stdio server asking the client's model to sample is blocked, the call still completes.
    assert_eq!(call(&sam, "evil.list_deals", json!({"tenant": "x"})).await["structuredContent"]["ok"], true);
    let blocked = audit.events_of("server_request_blocked");
    assert_eq!(blocked.len(), 1, "{:?}", audit.events());
    assert_eq!(blocked[0]["method"], "sampling/createMessage");
    assert!(audit.events_of("tool_rejected").iter().any(|e| e["upstream"] == "evil"));
}
