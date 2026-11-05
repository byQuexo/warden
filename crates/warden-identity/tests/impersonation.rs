#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! "Test as user": an admin console exchanges the operator's token for a read-only token
//! of another subject; the verifier marks the principal as impersonated.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use warden_core::{IdentityConfig, TokenError};
use warden_identity::{now_unix, ClientDef, Sts, StsConfig, Verifier, TOKEN_EXCHANGE_GRANT};

async fn start() -> (Arc<Sts>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let clients = HashMap::from([
        ("console".to_string(), ClientDef { secret: "c".into(), can_impersonate: true, ..Default::default() }),
        ("bot".to_string(), ClientDef { secret: "b".into(), ..Default::default() }),
    ]);
    let sts = Arc::new(Sts::new(StsConfig { issuer: url.clone(), token_ttl_s: 300, clients }, None).unwrap());
    let r = sts.clone().router();
    tokio::spawn(async move { axum::serve(listener, r).await.unwrap() });
    (sts, url)
}

fn identity(iss: &str, trusted: bool) -> IdentityConfig {
    let d = if trusted { format!("delegation_issuers: [{iss}]\n") } else { String::new() };
    IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - {{ issuer: {iss}, audience: https://gw/mcp, algorithms: [ES256], mapping: {{ preset: keycloak, attrs: {{ tenants: /tenants }} }} }}\n{d}scope_claim: ignore\n"
    ))
    .unwrap()
}

async fn exchange(url: &str, client: (&str, &str), subject_token: &str, extra: &[(&str, &str)]) -> (u16, Value) {
    let mut form = vec![("grant_type", TOKEN_EXCHANGE_GRANT), ("subject_token", subject_token)];
    form.extend_from_slice(extra);
    let r = reqwest::Client::new().post(format!("{url}/token")).basic_auth(client.0, Some(client.1)).form(&form).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn console_tests_as_user_with_a_read_only_token() {
    let (sts, url) = start().await;
    let ines = sts.user_token("ines", "console", &["it-admin"], json!({}), "https://gw/mcp", &[], 300).unwrap();
    let (status, body) =
        exchange(&url, ("console", "c"), &ines, &[("impersonate", "sven"), ("roles", "sales-rep"), ("claims", r#"{"tenants":["dach"]}"#)])
            .await;
    assert_eq!(status, 200, "{body}");
    let token = body["access_token"].as_str().unwrap();

    let p = Verifier::new(identity(&url, true)).verify(token, now_unix()).await.unwrap();
    assert_eq!(p.subject.id, "sven");
    assert_eq!(p.impersonated_by.as_deref(), Some("ines"));
    assert!(p.subject.roles.contains("sales-rep") && !p.subject.roles.contains("it-admin"), "{:?}", p.subject.roles);
    assert!(p.subject.attrs.contains_key("tenants"));

    // A verifier that does not trust this issuer for delegation refuses the token.
    let err = Verifier::new(identity(&url, false)).verify(token, now_unix()).await.unwrap_err();
    assert!(matches!(err, TokenError::DelegationIssuer(_)), "{err:?}");
}

#[tokio::test]
async fn impersonation_is_restricted() {
    let (sts, url) = start().await;
    let ines = sts.user_token("ines", "console", &["it-admin"], json!({}), "https://gw/mcp", &[], 300).unwrap();
    let bot_token = sts.user_token("ines", "bot", &["it-admin"], json!({}), "https://gw/mcp", &[], 300).unwrap();
    // A client without can_impersonate.
    assert_eq!(exchange(&url, ("bot", "b"), &bot_token, &[("impersonate", "sven")]).await.0, 403);
    // Reserved claims cannot be injected.
    let (s, _) = exchange(&url, ("console", "c"), &ines, &[("impersonate", "sven"), ("claims", r#"{"act":{"sub":"x"}}"#)]).await;
    assert_eq!(s, 400);
    // Not combined with delegation, not oneself.
    assert_eq!(exchange(&url, ("console", "c"), &ines, &[("impersonate", "sven"), ("delegate_to", "x")]).await.0, 400);
    assert_eq!(exchange(&url, ("console", "c"), &ines, &[("impersonate", "ines")]).await.0, 400);
}
