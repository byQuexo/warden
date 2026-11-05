#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! RFC 7662 introspection and RFC 7009 revocation: revoked tokens and removed users are
//! rejected immediately instead of when the token expires; opaque tokens are supported.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::post;
use axum::{Form, Json, Router};
use serde_json::json;
use warden_core::{IdentityConfig, TokenError};
use warden_identity::{now_unix, ClientDef, Sts, StsConfig, Verifier};

const AUD: &str = "https://gw.test/mcp";

async fn serve(r: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    url
}

async fn sts() -> (Arc<Sts>, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let clients = HashMap::from([
        ("gw".to_string(), ClientDef { secret: "gw-secret".into(), ..Default::default() }),
        ("console".to_string(), ClientDef { secret: "console-secret".into(), can_revoke_subjects: true, ..Default::default() }),
    ]);
    let sts = Arc::new(Sts::new(StsConfig { issuer: url.clone(), token_ttl_s: 300, clients }, None).unwrap());
    let r = sts.clone().router();
    tokio::spawn(async move { axum::serve(l, r).await.unwrap() });
    (sts, url)
}

fn identity(iss: &str, opaque_iss: &str) -> IdentityConfig {
    std::env::set_var("WARDEN_TEST_INTROSPECT_SECRET", "gw-secret");
    IdentityConfig::from_yaml_str(&format!(
        r#"
version: 1
issuers:
  - issuer: {iss}
    audience: {AUD}
    algorithms: [ES256]
    mapping: {{ preset: keycloak }}
    introspection: {{ endpoint: "{iss}/introspect", client_id: gw, secret_env: WARDEN_TEST_INTROSPECT_SECRET }}
  - issuer: {opaque_iss}
    audience: {AUD}
    mapping: {{ preset: generic-oidc }}
    introspection: {{ endpoint: "{opaque_iss}/introspect", client_id: gw }}
scope_claim: ignore
"#
    ))
    .unwrap()
}

async fn revoke(url: &str, client: (&str, &str), form: &[(&str, &str)]) -> u16 {
    reqwest::Client::new()
        .post(format!("{url}/revoke"))
        .basic_auth(client.0, Some(client.1))
        .form(form)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn revoked_tokens_and_subjects_are_rejected_immediately() {
    let (sts, url) = sts().await;
    let v = Verifier::new(identity(&url, "https://opaque.test"));
    let t = sts.user_token("sven", "acme-bot", &["sales-rep"], json!({}), AUD, &[], 300).unwrap();
    assert_eq!(v.verify(&t, now_unix()).await.unwrap().subject.id, "sven");

    // RFC 7009: revoke this one token.
    assert_eq!(revoke(&url, ("gw", "gw-secret"), &[("token", &t)]).await, 200);
    assert_eq!(v.verify(&t, now_unix()).await, Err(TokenError::Revoked));

    // Revoke every current token of a subject (e.g. a role was removed in the console).
    let t2 = sts.user_token("sara", "acme-bot", &["sales-lead"], json!({}), AUD, &[], 300).unwrap();
    assert!(v.verify(&t2, now_unix()).await.is_ok());
    assert_eq!(revoke(&url, ("gw", "gw-secret"), &[("sub", "sara")]).await, 403, "only privileged clients revoke subjects");
    assert_eq!(revoke(&url, ("console", "console-secret"), &[("sub", "sara")]).await, 200);
    assert_eq!(v.verify(&t2, now_unix()).await, Err(TokenError::Revoked));
    // A token issued afterwards (with the new roles) works again.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let t3 = sts.user_token("sara", "acme-bot", &["sales-rep"], json!({}), AUD, &[], 300).unwrap();
    assert!(v.verify(&t3, now_unix()).await.is_ok());

    // A revoked token can no longer be exchanged either.
    let form = [
        ("grant_type", warden_identity::TOKEN_EXCHANGE_GRANT),
        ("client_id", "gw"),
        ("client_secret", "gw-secret"),
        ("subject_token", t.as_str()),
    ];
    let s = reqwest::Client::new().post(format!("{url}/token")).form(&form).send().await.unwrap().status();
    assert_eq!(s, 400);
}

#[tokio::test]
async fn opaque_tokens_are_checked_by_introspection() {
    let (_, url) = sts().await;
    let opaque = Router::new().route(
        "/introspect",
        post(|Form(f): Form<HashMap<String, String>>| async move {
            let exp = now_unix() + 300;
            Json(match f.get("token").map(String::as_str) {
                Some("opaque-good") => json!({"active": true, "sub": "robot-1", "client_id": "acme-bot", "aud": AUD, "exp": exp, "scope": "crm:read", "roles": ["reader"]}),
                _ => json!({"active": false}),
            })
        }),
    );
    let opaque_url = serve(opaque).await;
    let v = Verifier::new(identity(&url, &opaque_url));
    let p = v.verify("opaque-good", now_unix()).await.unwrap();
    assert_eq!(p.subject.id, "robot-1");
    assert_eq!(p.agent, "acme-bot");
    assert_eq!(p.issuer.as_deref(), Some(opaque_url.as_str()));
    assert_eq!(v.verify("opaque-bad", now_unix()).await, Err(TokenError::Revoked));
}
