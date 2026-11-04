//! End-to-end harness: a real STS (OIDC discovery + JWKS + token exchange), mock MCP
//! upstreams, a mock approval webhook and the gateway, all on ephemeral ports.
#![allow(dead_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_scope_audit::{generate_signing_key, signing_key_from_b64, verifying_key_from_b64, JsonlConfig, JsonlSink, MemorySink, MultiSink};
use agent_scope_core::lock::definition_hash;
use agent_scope_core::{Engine, IdentityConfig, Lock};
use agent_scope_gateway::{Gateway, UpstreamAuth, WebhookApprover};
use agent_scope_identity::{ClientDef, Sts, StsConfig, Verifier};
use agent_scope_mcp::McpClient;
use agent_scope_testkit::{profile_state, MockApprover, MockUpstream, Profile};
use ed25519_dalek::VerifyingKey;
use serde_json::{json, Value};

pub const AUD: &str = "http://gw.test/mcp";
pub const POLICY: &str = include_str!("../../../../examples/acme/policy.yaml");
pub const CATALOG: &str = include_str!("../../../../examples/acme/catalog.yaml");
pub const ALL_SCOPES: &[&str] = &[
    "hr:read", "hr:salary", "crm:read", "crm:write", "crm:export", "ticket:read", "ticket:write", "docs:hr", "docs:it", "docs:sales", "admin",
];

pub struct Harness {
    pub gw: Gateway,
    pub url: String,
    pub admin_url: String,
    pub sts: Arc<Sts>,
    pub sts_url: String,
    pub hr: MockUpstream,
    pub crm: MockUpstream,
    pub docs: MockUpstream,
    pub evil: MockUpstream,
    pub approver: MockApprover,
    pub memory: Arc<MemorySink>,
    pub audit_dir: tempfile::TempDir,
    pub audit_pubkey: VerifyingKey,
    pub jsonl: Arc<JsonlSink>,
    pub kill_file: PathBuf,
}

/// The acme catalog plus a test-only entry for the misbehaving upstream.
pub fn catalog() -> String {
    CATALOG.replacen("tool:\n", "tool:\n  evil.list_deals:      { scopes: [crm:read], sensitivity: read }\n", 1)
}

/// Pin the namespaced definitions every mock upstream advertises right now.
fn lock_for(upstreams: &[(&str, Profile)]) -> Lock {
    let mut lock = Lock::new();
    for (ns, profile) in upstreams {
        for t in profile_state(*profile).tools {
            let name = t["name"].as_str().unwrap_or("");
            if name.is_ascii() {
                lock.pin("tool", &format!("{ns}.{name}"), &definition_hash(&t));
            }
        }
    }
    lock
}

async fn bind() -> (tokio::net::TcpListener, String) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    (l, url)
}

pub async fn harness() -> Harness {
    // STS = the IdP for this test (Keycloak-shaped tokens) and the token-exchange service.
    let (sts_l, sts_url) = bind().await;
    let mut clients = HashMap::new();
    clients.insert("acme-bot".into(), ClientDef { secret: "bot-secret".into(), ..Default::default() });
    clients.insert(
        "gw".into(),
        ClientDef {
            secret: "gw-secret".into(),
            accept_audiences: vec![AUD.into()],
            may_exchange_to: vec!["hr-mcp".into(), "crm-mcp".into(), "docs-mcp".into()],
            ..Default::default()
        },
    );
    let engine_for_sts = Engine::builder().policy_yaml(POLICY).catalog_yaml(&catalog()).build().unwrap();
    let policy = engine_for_sts.policy().clone();
    let sts = Sts::new(StsConfig { issuer: sts_url.clone(), token_ttl_s: 300, clients }, None)
        .unwrap()
        .with_delegation_check(Arc::new(move |from: &str, to: &str| {
            policy.agents.get(from).is_some_and(|a| a.delegation.may_delegate_to.iter().any(|t| t == to))
        }));
    let sts = Arc::new(sts);
    let r = sts.clone().router();
    tokio::spawn(async move { axum::serve(sts_l, r).await.unwrap() });

    let (hr, crm, docs, evil) = (
        MockUpstream::spawn(Profile::Hr).await,
        MockUpstream::spawn(Profile::Crm).await,
        MockUpstream::spawn(Profile::Docs).await,
        MockUpstream::spawn(Profile::Evil).await,
    );
    let approver = MockApprover::spawn().await;

    let identity = IdentityConfig::from_yaml_str(&format!(
        r#"
version: 1
issuers:
  - issuer: {sts_url}
    audience: {AUD}
    algorithms: [ES256]
    mapping: {{ preset: keycloak, attrs: {{ org_unit: /org_unit, tenants: /tenants }} }}
delegation_issuers: [{sts_url}]
"#
    ))
    .unwrap();

    let lock = lock_for(&[("hr", Profile::Hr), ("crm", Profile::Crm), ("evil", Profile::Evil)]);
    let engine = Engine::builder().policy_yaml(POLICY).catalog_yaml(&catalog()).lock(Some(lock)).build().unwrap();

    let audit_dir = tempfile::tempdir().unwrap();
    let (sk, pk) = generate_signing_key();
    let jsonl = Arc::new(
        JsonlSink::open(JsonlConfig {
            dir: audit_dir.path().join("audit"),
            chain: "gw-test".into(),
            signing_key: Some(signing_key_from_b64(&sk).unwrap()),
            checkpoint_every: 25,
        })
        .unwrap(),
    );
    let memory = MemorySink::new();
    let kill_file = audit_dir.path().join("kill");
    let token_url = format!("{sts_url}/token");
    let exchange = |aud: &str| UpstreamAuth::TokenExchange {
        token_url: token_url.clone(),
        client_id: "gw".into(),
        secret: "gw-secret".into(),
        audience: aud.into(),
        scope: None,
    };

    let gw = Gateway::builder()
        .engine(engine)
        .verifier(Verifier::new(identity))
        .public_url(AUD)
        .upstream("hr", &hr.url, exchange("hr-mcp"), vec![])
        .upstream("crm", &crm.url, exchange("crm-mcp"), vec![])
        .upstream(
            "docs",
            &docs.url,
            UpstreamAuth::ClientCredentials { token_url: token_url.clone(), client_id: "gw".into(), secret: "gw-secret".into(), audience: Some("docs-mcp".into()), scope: None },
            vec!["docs://".into()],
        )
        .upstream("evil", &evil.url, UpstreamAuth::None, vec![])
        .approver(Arc::new(WebhookApprover::new(approver.url.clone(), Some(b"hook-secret".to_vec()), Duration::from_secs(5))))
        .approval_timeout(Duration::from_millis(1500))
        .progress_interval(Duration::from_millis(100))
        .audit(Arc::new(MultiSink(vec![memory.clone(), jsonl.clone()])))
        .hmac_key(b"test-hmac-key".to_vec())
        .kill_switch_file(kill_file.clone())
        .definition_ttl(Duration::ZERO)
        .admin_token(Some("admin-secret".into()))
        .build()
        .unwrap();

    let (gl, url) = bind().await;
    let (al, admin_url) = bind().await;
    tokio::spawn(gw.clone().serve(gl, Some(al)));

    Harness {
        gw,
        url: format!("{url}/mcp"),
        admin_url,
        sts,
        sts_url,
        hr,
        crm,
        docs,
        evil,
        approver,
        memory,
        audit_dir,
        audit_pubkey: verifying_key_from_b64(&pk).unwrap(),
        jsonl,
        kill_file,
    }
}

impl Harness {
    pub fn token(&self, user: &str) -> String {
        let (roles, attrs): (&[&str], Value) = match user {
            "hanna" => (&["hr-member"], json!({"org_unit": "hr"})),
            "henrik" => (&["hr-lead"], json!({"org_unit": "hr"})),
            "sven" => (&["sales-rep"], json!({"tenants": ["dach"]})),
            "sara" => (&["sales-lead"], json!({"tenants": ["dach", "enterprise"]})),
            "ines" => (&["it-admin"], json!({})),
            other => panic!("unknown test user {other}"),
        };
        self.sts.user_token(user, "acme-bot", roles, attrs, AUD, ALL_SCOPES, 300).unwrap()
    }

    pub fn client(&self) -> McpClient {
        McpClient::new(self.url.clone())
    }

    pub async fn tool_names(&self, token: &str) -> Vec<String> {
        let o = self.client().call(Some(token), "tools/list", json!({})).await.unwrap();
        let r = o.result.unwrap();
        r["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// Call a tool and return the result object (tool errors included).
    pub async fn call_tool(&self, token: &str, name: &str, args: Value) -> Value {
        let o = self.client().call(Some(token), "tools/call", json!({"name": name, "arguments": args})).await.unwrap();
        o.result.unwrap_or_else(|(c, m)| json!({"rpc_error": c, "message": m}))
    }

    pub async fn admin(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let mut r = reqwest::Client::new().request(method, format!("{}{path}", self.admin_url)).bearer_auth("admin-secret");
        if let Some(b) = body {
            r = r.json(&b);
        }
        let resp = r.send().await.unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap_or(Value::Null))
    }
}

pub fn is_denied(result: &Value) -> bool {
    result["isError"] == true && result["content"][0]["text"].as_str().is_some_and(|t| t.contains("not"))
}

pub fn claims_of(jwt: &str) -> Value {
    use base64::Engine as _;
    let p = jwt.split('.').nth(1).unwrap();
    serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).unwrap()).unwrap()
}
