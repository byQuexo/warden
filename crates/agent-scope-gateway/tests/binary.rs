//! Runs the real `agent-scope-gateway` binary from a `gateway.yaml`, against an in-process
//! STS and mock upstream: config loading, env-var secrets, audit files and the CLI wiring.

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use agent_scope_identity::{ClientDef, Sts, StsConfig};
use agent_scope_mcp::McpClient;
use agent_scope_testkit::{MockUpstream, Profile};
use serde_json::json;

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::test]
async fn gateway_binary_serves_a_config_file() {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sts_url = format!("http://{}", l.local_addr().unwrap());
    let sts = Arc::new(Sts::new(StsConfig { issuer: sts_url.clone(), token_ttl_s: 300, clients: HashMap::from([("helpdesk-bot".to_string(), ClientDef { secret: "x".into(), ..Default::default() })]) }, None).unwrap());
    let r = sts.clone().router();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    let ticket = MockUpstream::spawn(Profile::Ticket).await;

    let (port, admin_port) = (free_port(), free_port());
    let aud = format!("http://127.0.0.1:{port}/mcp");
    let dir = tempfile::tempdir().unwrap();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/minimal");
    for f in ["policy.yaml", "catalog.yaml"] {
        std::fs::copy(root.join(f), dir.path().join(f)).unwrap();
    }
    std::fs::write(
        dir.path().join("identity.yaml"),
        format!("version: 1\nissuers:\n  - issuer: {sts_url}\n    audience: {aud}\n    algorithms: [ES256]\n    mapping: {{ preset: keycloak }}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("gateway.yaml"),
        format!(
            r#"
listen: 127.0.0.1:{port}
admin_listen: 127.0.0.1:{admin_port}
admin_token_env: TEST_ADMIN_TOKEN
public_url: {aud}
identity: identity.yaml
policy: {{ catalog: catalog.yaml, policy: policy.yaml, reload_ms: 0 }}
upstreams:
  ticket: {{ url: {} }}
audit:
  sinks:
    - {{ type: jsonl, dir: audit, chain: bin, checkpoint_key_env: TEST_AUDIT_KEY, checkpoint_every: 1 }}
  hmac_key_env: TEST_HMAC
"#,
            ticket.url
        ),
    )
    .unwrap();
    let (sk, pk) = agent_scope_audit::generate_signing_key();
    let child = Command::new(env!("CARGO_BIN_EXE_agent-scope-gateway"))
        .args(["--config", dir.path().join("gateway.yaml").to_str().unwrap()])
        .env("TEST_ADMIN_TOKEN", "adm")
        .env("TEST_AUDIT_KEY", &sk)
        .env("TEST_HMAC", "hmac")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = Kill(child);

    let health = format!("http://127.0.0.1:{port}/healthz");
    let mut up = false;
    for _ in 0..100 {
        if reqwest::get(&health).await.is_ok_and(|r| r.status().is_success()) {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "gateway binary did not start");

    let client = McpClient::new(aud.clone());
    let vera = sts.user_token("vera", "helpdesk-bot", &["viewer"], json!({}), &aud, &["ticket:read", "ticket:write"], 300).unwrap();
    let sam = sts.user_token("sam", "helpdesk-bot", &["support"], json!({}), &aud, &["ticket:read", "ticket:write"], 300).unwrap();
    let list = |t: String| {
        let c = &client;
        async move {
            let r = c.call(Some(&t), "tools/list", json!({})).await.unwrap().result.unwrap();
            let mut v: Vec<String> = r["tools"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap().to_string()).collect();
            v.sort();
            v
        }
    };
    assert_eq!(list(vera.clone()).await, vec!["ticket.list"]);
    assert_eq!(list(sam.clone()).await, vec!["ticket.close", "ticket.list"]);
    let r = client.call(Some(&sam), "tools/call", json!({"name": "ticket.close", "arguments": {"id": "T-1 OR 1=1"}})).await.unwrap().result.unwrap();
    assert_eq!(r["isError"], true);
    let r = client.call(Some(&sam), "tools/call", json!({"name": "ticket.close", "arguments": {"id": "T-42"}})).await.unwrap().result.unwrap();
    assert_eq!(r["structuredContent"]["ok"], true);

    // Admin API is up and protected.
    let a = reqwest::Client::new().get(format!("http://127.0.0.1:{admin_port}/v1/policy")).bearer_auth("adm").send().await.unwrap();
    assert_eq!(a.status(), 200);

    // Every decision is in a verifiable, signed chain.
    let report = agent_scope_audit::verify_dir(&dir.path().join("audit"), Some(&agent_scope_audit::verifying_key_from_b64(&pk).unwrap()), 1).unwrap();
    assert!(report.chains["bin"].events >= 4, "{report:?}");
}

#[test]
fn insecure_settings_require_dev_flag() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("identity.yaml"), "version: 1\nissuers:\n  - { issuer: http://idp.example.com, audience: a, mapping: { preset: keycloak } }\n").unwrap();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/minimal");
    for f in ["policy.yaml", "catalog.yaml"] {
        std::fs::copy(root.join(f), dir.path().join(f)).unwrap();
    }
    std::fs::write(
        dir.path().join("gateway.yaml"),
        "public_url: http://x/mcp\nidentity: identity.yaml\npolicy: { catalog: catalog.yaml, policy: policy.yaml }\napproval: { approver: auto-approve }\naudit: { sinks: [ { type: stdout } ] }\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agent-scope-gateway")).args(["--config", dir.path().join("gateway.yaml").to_str().unwrap()]).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("plain HTTP") || err.contains("--dev"), "{err}");
}
