#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use agent_scope_core::{IdentityConfig, TokenError};
use agent_scope_identity::{ClientDef, Sts, StsConfig, Verifier, TOKEN_EXCHANGE_GRANT};
use base64::Engine as _;
use serde_json::{json, Value};

async fn start() -> (Arc<Sts>, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut clients = HashMap::new();
    clients.insert("acme-bot".to_string(), ClientDef { secret: "bot-secret".into(), ..Default::default() });
    clients.insert(
        "gw".to_string(),
        ClientDef {
            secret: "gw-secret".into(),
            accept_audiences: vec!["https://gw/mcp".into()],
            may_exchange_to: vec!["crm-mcp".into()],
            ..Default::default()
        },
    );
    let sts = Sts::new(StsConfig { issuer: url.clone(), token_ttl_s: 300, clients }, None)
        .unwrap()
        .with_delegation_check(Arc::new(|from: &str, to: &str| from == "acme-bot" && to == "acme-action"));
    let sts = Arc::new(sts);
    let router = sts.clone().router();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (sts, url)
}

fn identity(iss: &str) -> IdentityConfig {
    IdentityConfig::from_yaml_str(&format!(
        "version: 1\nissuers:\n  - issuer: {iss}\n    audience: https://gw/mcp\n    algorithms: [ES256, RS256]\n    mapping: {{ preset: keycloak, attrs: {{ org_unit: /org_unit }} }}\ndelegation_issuers: [{iss}]\n"
    ))
    .unwrap()
}

#[tokio::test]
async fn verifies_via_oidc_discovery() {
    let (sts, url) = start().await;
    let token = sts.user_token("hanna", "acme-bot", &["hr-member"], json!({"org_unit": "hr"}), "https://gw/mcp", &["hr:read"], 60).unwrap();
    let v = Verifier::new(identity(&url));
    let p = v.verify(&token, agent_scope_identity::now_unix()).await.unwrap();
    assert_eq!(p.subject.id, "hanna");
    assert!(p.subject.roles.contains("hr-member"));
}

fn forge(header: Value, payload: Value) -> String {
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("{}.{}.", b.encode(header.to_string()), b.encode(payload.to_string()))
}

#[tokio::test]
async fn rejects_forged_and_wrong_tokens() {
    let (sts, url) = start().await;
    let v = Verifier::new(identity(&url)).with_refresh_interval(Duration::from_secs(60));
    let now = agent_scope_identity::now_unix();
    let claims = json!({"iss": url, "sub": "x", "azp": "acme-bot", "aud": "https://gw/mcp", "exp": now + 60, "typ": "Bearer"});

    // alg: none
    let none = forge(json!({"alg": "none", "typ": "JWT"}), claims.clone());
    assert!(matches!(v.verify(&none, now).await, Err(TokenError::Invalid(_))));
    // HS256 (classic key confusion) is not an allowed algorithm
    let hs = forge(json!({"alg": "HS256", "kid": "x"}), claims.clone()) + "c2ln";
    assert!(matches!(v.verify(&hs, now).await, Err(TokenError::Invalid(_))));
    // unknown kid
    let unknown = forge(json!({"alg": "ES256", "kid": "nope"}), claims.clone()) + "c2ln";
    assert!(matches!(v.verify(&unknown, now).await, Err(TokenError::Invalid(_))));
    // tampered payload with a valid signature from another token
    let good = sts.user_token("hanna", "acme-bot", &["hr-member"], json!({}), "https://gw/mcp", &[], 60).unwrap();
    let parts: Vec<&str> = good.split('.').collect();
    let mut evil_claims: Value =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    evil_claims["realm_access"]["roles"] = json!(["hr-lead"]);
    let tampered =
        format!("{}.{}.{}", parts[0], base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(evil_claims.to_string()), parts[2]);
    assert!(matches!(v.verify(&tampered, now).await, Err(TokenError::Invalid(_))));
    // wrong audience, expired
    let wrong_aud = sts.user_token("hanna", "acme-bot", &[], json!({}), "https://other", &[], 60).unwrap();
    assert!(matches!(v.verify(&wrong_aud, now).await, Err(TokenError::Audience(_))));
    let expired = sts.user_token("hanna", "acme-bot", &[], json!({}), "https://gw/mcp", &[], -3600).unwrap();
    assert_eq!(v.verify(&expired, now).await, Err(TokenError::Expired));
}

async fn post(url: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let r = reqwest::Client::new().post(format!("{url}/token")).form(form).send().await.unwrap();
    (r.status().as_u16(), r.json().await.unwrap())
}

#[tokio::test]
async fn token_exchange_and_delegation() {
    let (sts, url) = start().await;
    let v = Verifier::new(identity(&url));
    let now = agent_scope_identity::now_unix();
    let user = sts.user_token("sven", "acme-bot", &["sales-rep"], json!({}), "https://gw/mcp", &["crm:read", "crm:write"], 120).unwrap();

    // The bot delegates to acme-action: the act chain records the bot.
    let (s, body) = post(
        &url,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", "acme-bot"),
            ("client_secret", "bot-secret"),
            ("subject_token", &user),
            ("delegate_to", "acme-action"),
            ("audience", "https://gw/mcp"),
        ],
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let p = v.verify(body["access_token"].as_str().unwrap(), now).await.unwrap();
    assert_eq!(p.agent, "acme-action");
    assert_eq!(p.act, vec!["acme-bot".to_string()]);
    assert_eq!(p.subject.id, "sven");

    // Disallowed delegation edge.
    let (s, _) = post(
        &url,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", "acme-bot"),
            ("client_secret", "bot-secret"),
            ("subject_token", &user),
            ("delegate_to", "acme-evil"),
        ],
    )
    .await;
    assert_eq!(s, 403);

    // The gateway exchanges the user token for an upstream token with a narrower audience.
    let (s, body) = post(
        &url,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", "gw"),
            ("client_secret", "gw-secret"),
            ("subject_token", &user),
            ("audience", "crm-mcp"),
            ("scope", "crm:read"),
        ],
    )
    .await;
    assert_eq!(s, 200, "{body}");
    let (claims, _) = v.verify_signature(body["access_token"].as_str().unwrap()).await.unwrap();
    assert_eq!(claims["aud"], "crm-mcp");
    assert_eq!(claims["scope"], "crm:read");
    assert_eq!(claims["sub"], "sven");

    // The gateway may not mint tokens for arbitrary audiences.
    let (s, _) = post(
        &url,
        &[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("client_id", "gw"),
            ("client_secret", "gw-secret"),
            ("subject_token", &user),
            ("audience", "hr-mcp"),
        ],
    )
    .await;
    assert_eq!(s, 400);

    // Wrong secret.
    let (s, _) = post(&url, &[("grant_type", "client_credentials"), ("client_id", "gw"), ("client_secret", "nope")]).await;
    assert_eq!(s, 401);
}
