#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The `warden sts` binary in production mode: trusts an external IdP for subject tokens,
//! issues delegation tokens with `act` chains, revokes, and refuses insecure settings.

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use warden_core::IdentityConfig;
use warden_identity::{now_unix, Sts, StsConfig, Verifier, TOKEN_EXCHANGE_GRANT};

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
async fn sts_binary_exchanges_idp_tokens_into_delegation_tokens() {
    // The "IdP" (stands in for Keycloak): issues user access tokens, serves JWKS.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_url = format!("http://{}", l.local_addr().unwrap());
    let idp = Arc::new(Sts::new(StsConfig { issuer: idp_url.clone(), token_ttl_s: 300, clients: HashMap::new() }, None).unwrap());
    let r = idp.clone().router();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });

    let port = free_port();
    let sts_url = format!("http://127.0.0.1:{port}");
    let dir = tempfile::tempdir().unwrap();
    let key = Command::new(env!("CARGO_BIN_EXE_warden")).args(["dev", "keygen"]).output().unwrap();
    std::fs::write(dir.path().join("sts-key.pem"), key.stdout).unwrap();
    std::fs::write(
        dir.path().join("trust.yaml"),
        format!(
            "version: 1\nissuers:\n  - {{ issuer: {idp_url}, audience: acme-bot, algorithms: [ES256], mapping: {{ preset: keycloak }} }}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("policy.yaml"),
        "version: 1\nagents:\n  acme-bot: { delegation: { may_delegate_to: [acme-action] } }\n  acme-action: { delegation: { max_depth: 1 } }\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("sts.yaml"),
        format!(
            "issuer: {sts_url}\nkey_file: sts-key.pem\ntrust: trust.yaml\npolicy: policy.yaml\nclients:\n  acme-bot: {{ secret_env: TEST_BOT_SECRET }}\n  console: {{ secret_env: TEST_CONSOLE_SECRET, can_revoke_subjects: true }}\n"
        ),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(["sts", "--config", dir.path().join("sts.yaml").to_str().unwrap(), "--listen", &format!("127.0.0.1:{port}")])
        .env("TEST_BOT_SECRET", "bot")
        .env("TEST_CONSOLE_SECRET", "console")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _guard = Kill(child);
    let http = reqwest::Client::new();
    let mut up = false;
    for _ in 0..100 {
        if http.get(format!("{sts_url}/jwks")).send().await.is_ok_and(|r| r.status().is_success()) {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "warden sts did not start");

    // A user token from the IdP, held by acme-bot.
    let user = idp.user_token("sven", "acme-bot", &["sales-rep"], json!({}), "acme-bot", &[], 300).unwrap();
    let exchange = |delegate: &'static str| {
        let http = http.clone();
        let (url, user) = (sts_url.clone(), user.clone());
        async move {
            http.post(format!("{url}/token"))
                .basic_auth("acme-bot", Some("bot"))
                .form(&[
                    ("grant_type", TOKEN_EXCHANGE_GRANT),
                    ("subject_token", user.as_str()),
                    ("delegate_to", delegate),
                    ("audience", "https://gw/mcp"),
                ])
                .send()
                .await
                .unwrap()
        }
    };
    let r = exchange("acme-action").await;
    assert_eq!(r.status(), 200);
    let delegated = r.json::<Value>().await.unwrap()["access_token"].as_str().unwrap().to_string();

    // The gateway side trusts the STS as a delegation issuer and sees the chain.
    let gw_identity = IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - {{ issuer: {sts_url}, audience: https://gw/mcp, algorithms: [ES256], mapping: {{ preset: keycloak }} }}\ndelegation_issuers: [{sts_url}]\nscope_claim: ignore\n"
    ))
    .unwrap();
    let p = Verifier::new(gw_identity).verify(&delegated, now_unix()).await.unwrap();
    assert_eq!((p.subject.id.as_str(), p.agent.as_str()), ("sven", "acme-action"));
    assert_eq!(p.act, vec!["acme-bot".to_string()]);

    // Edges the policy does not allow are refused; a wrong secret is refused.
    assert_eq!(exchange("rogue-agent").await.status(), 403);
    let bad = http
        .post(format!("{sts_url}/token"))
        .basic_auth("acme-bot", Some("nope"))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);

    // After the console revokes the user, the IdP token can no longer be exchanged.
    let rv = http.post(format!("{sts_url}/revoke")).basic_auth("console", Some("console")).form(&[("sub", "sven")]).send().await.unwrap();
    assert_eq!(rv.status(), 200);
    assert_eq!(exchange("acme-action").await.status(), 400);
}

#[test]
fn production_mode_refuses_insecure_settings() {
    let dir = tempfile::tempdir().unwrap();
    let run = |yaml: &str| {
        std::fs::write(dir.path().join("sts.yaml"), yaml).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_warden"))
            .args(["sts", "--config", dir.path().join("sts.yaml").to_str().unwrap()])
            .output()
            .unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stderr).to_string())
    };
    let (ok, err) = run("issuer: http://sts.example.com\nkey_file: k.pem\n");
    assert!(!ok && err.contains("plain HTTP"), "{err}");
    let (ok, err) = run("issuer: https://sts.example.com\nkey_file: k.pem\nclients:\n  a: { secret: literal }\n");
    assert!(!ok && err.contains("only allowed with --dev"), "{err}");
    let (ok, err) = run("issuer: https://sts.example.com\nkey_file: missing.pem\n");
    assert!(!ok && err.contains("not found"), "{err}");
}
