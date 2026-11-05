//! A small OAuth 2.0 security token service.
//!
//! * `client_credentials` for service accounts and gateways
//! * RFC 8693 token exchange, including a `delegate_to` extension that appends the
//!   delegating agent to the `act` chain: most IdPs cannot issue delegation chains
//! * OIDC discovery + JWKS, so any verifier (including warden's) can trust it
//!
//! It never authenticates humans; user identity always comes from a subject token issued by
//! a trusted IdP (or by this STS in dev mode).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use base64::Engine as _;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{now_unix, Verifier};

pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// `(from_agent, to_agent) -> allowed?`, usually backed by the policy's `may_delegate_to`.
pub type DelegationCheck = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDef {
    pub secret: String,
    /// Realm roles of the client's service account (client_credentials tokens).
    #[serde(default)]
    pub roles: Vec<String>,
    /// This client may exchange subject tokens whose `aud` contains one of these.
    #[serde(default)]
    pub accept_audiences: Vec<String>,
    /// Audiences this client may request. Empty = any.
    #[serde(default)]
    pub may_exchange_to: Vec<String>,
    /// May revoke every token of a subject (`POST /revoke` with `sub=`), e.g. an admin console.
    #[serde(default)]
    pub can_revoke_subjects: bool,
    /// May issue "test as user" tokens (`impersonate=<subject>`); the result is read-only.
    #[serde(default)]
    pub can_impersonate: bool,
}

#[derive(Clone, Debug)]
pub struct StsConfig {
    /// Public base URL; becomes `iss`.
    pub issuer: String,
    pub token_ttl_s: i64,
    pub clients: HashMap<String, ClientDef>,
}

pub struct Sts {
    cfg: StsConfig,
    enc: EncodingKey,
    dec: DecodingKey,
    jwk: Jwk,
    kid: String,
    pem: String,
    external: Option<Verifier>,
    delegation: Option<DelegationCheck>,
    /// Revoked token ids (RFC 7009).
    revoked_jti: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Subjects whose tokens issued before the given time are revoked.
    revoked_subjects: std::sync::Mutex<HashMap<String, i64>>,
}

#[derive(Debug)]
pub struct StsError {
    status: StatusCode,
    code: &'static str,
    description: String,
}

impl StsError {
    fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self { status, code, description: description.into() }
    }
}

impl IntoResponse for StsError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.code, "error_description": self.description}))).into_response()
    }
}

impl Sts {
    /// Create an STS. With `pem = None` a fresh ES256 key is generated.
    pub fn new(cfg: StsConfig, pem: Option<&str>) -> Result<Self, String> {
        let sk = match pem {
            Some(p) => p256::SecretKey::from_pkcs8_pem(p).map_err(|e| format!("signing key: {e}"))?,
            None => p256::SecretKey::random(&mut rand::rngs::OsRng),
        };
        let pem = sk.to_pkcs8_pem(LineEnding::LF).map_err(|e| e.to_string())?.to_string();
        let point = sk.public_key().to_encoded_point(false);
        let (x, y) = match (point.x(), point.y()) {
            (Some(x), Some(y)) => (x.to_vec(), y.to_vec()),
            _ => return Err("invalid public key".into()),
        };
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let kid = hex::encode(&Sha256::digest([x.as_slice(), y.as_slice()].concat())[..8]);
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC", "crv": "P-256", "x": b64.encode(&x), "y": b64.encode(&y),
            "kid": kid, "alg": "ES256", "use": "sig"
        }))
        .map_err(|e| e.to_string())?;
        let enc = EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| e.to_string())?;
        let dec = DecodingKey::from_jwk(&jwk).map_err(|e| e.to_string())?;
        Ok(Self {
            cfg,
            enc,
            dec,
            jwk,
            kid,
            pem,
            external: None,
            delegation: None,
            revoked_jti: std::sync::Mutex::new(std::collections::HashSet::new()),
            revoked_subjects: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Trust subject tokens from external issuers (e.g. Keycloak) for token exchange.
    pub fn with_external_verifier(mut self, v: Verifier) -> Self {
        self.external = Some(v);
        self
    }

    pub fn with_delegation_check(mut self, f: DelegationCheck) -> Self {
        self.delegation = Some(f);
        self
    }

    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }
    pub fn pem(&self) -> &str {
        &self.pem
    }
    pub fn jwks(&self) -> JwkSet {
        JwkSet { keys: vec![self.jwk.clone()] }
    }

    /// Sign arbitrary claims. Fills `iss`, `iat` and (if missing) `exp`.
    pub fn issue(&self, mut claims: Value) -> Result<String, String> {
        let now = now_unix();
        if let Value::Object(m) = &mut claims {
            m.insert("iss".into(), json!(self.cfg.issuer));
            m.insert("iat".into(), json!(now));
            m.insert("jti".into(), json!(hex::encode(rand::random::<[u8; 12]>())));
            m.entry("exp").or_insert(json!(now + self.cfg.token_ttl_s));
        }
        let mut h = Header::new(Algorithm::ES256);
        h.kid = Some(self.kid.clone());
        encode(&h, &claims, &self.enc).map_err(|e| e.to_string())
    }

    /// A Keycloak-shaped user access token (dev mode and tests).
    #[allow(clippy::too_many_arguments)]
    pub fn user_token(
        &self,
        subject: &str,
        agent: &str,
        roles: &[&str],
        attrs: Value,
        audience: &str,
        scopes: &[&str],
        ttl_s: i64,
    ) -> Result<String, String> {
        let mut c = json!({
            "sub": subject, "azp": agent, "aud": audience, "typ": "Bearer",
            "preferred_username": subject,
            "realm_access": {"roles": roles},
            "scope": scopes.join(" "),
            "exp": now_unix() + ttl_s,
        });
        if let (Value::Object(m), Value::Object(a)) = (&mut c, attrs) {
            m.extend(a);
        }
        self.issue(c)
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/introspect", post(introspect_endpoint))
            .route("/revoke", post(revoke_endpoint))
            .with_state(self)
    }

    async fn verify_subject(&self, token: &str) -> Result<Value, StsError> {
        let invalid = |m: String| StsError::new(StatusCode::BAD_REQUEST, "invalid_grant", m);
        let header = jsonwebtoken::decode_header(token).map_err(|e| invalid(e.to_string()))?;
        let claims = if header.kid.as_deref() == Some(self.kid.as_str()) {
            let mut v = Validation::new(Algorithm::ES256);
            v.validate_aud = false;
            v.required_spec_claims.clear();
            v.set_issuer(&[self.cfg.issuer.as_str()]);
            decode::<Value>(token, &self.dec, &v).map_err(|e| invalid(e.to_string()))?.claims
        } else if let Some(ext) = &self.external {
            ext.verify_signature(token).await.map_err(|e| invalid(e.to_string()))?.0
        } else {
            return Err(invalid("subject token issuer is not trusted".into()));
        };
        let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
        if exp < now_unix() {
            return Err(invalid("subject token expired".into()));
        }
        if self.is_revoked(&claims) {
            return Err(invalid("subject token was revoked".into()));
        }
        Ok(claims)
    }

    fn is_revoked(&self, claims: &Value) -> bool {
        let jti = claims.get("jti").and_then(Value::as_str);
        if jti.is_some_and(|j| self.revoked_jti.lock().is_ok_and(|r| r.contains(j))) {
            return true;
        }
        let sub = claims.get("sub").and_then(Value::as_str).unwrap_or("");
        let iat = claims.get("iat").and_then(Value::as_i64).unwrap_or(0);
        self.revoked_subjects.lock().is_ok_and(|r| r.get(sub).is_some_and(|before| iat <= *before))
    }

    /// RFC 7662 introspection of tokens this STS issued (or trusts as subject tokens).
    pub async fn introspect(&self, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<Value, StsError> {
        self.authenticate(headers, form)?;
        let Some(token) = form.get("token") else {
            return Err(StsError::new(StatusCode::BAD_REQUEST, "invalid_request", "token is required"));
        };
        Ok(match self.verify_subject(token).await {
            Ok(Value::Object(mut claims)) => {
                claims.insert("active".into(), json!(true));
                let azp = claims.get("azp").cloned().unwrap_or(Value::Null);
                claims.entry("client_id").or_insert(azp);
                Value::Object(claims)
            }
            _ => json!({"active": false}),
        })
    }

    /// RFC 7009 revocation. Extension: `sub=<subject>` revokes all of a subject's current
    /// tokens (clients with `can_revoke_subjects`), e.g. after a role was removed.
    pub async fn revoke(&self, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<(), StsError> {
        let (_, client) = self.authenticate(headers, form)?;
        if let Some(sub) = form.get("sub") {
            if !client.can_revoke_subjects {
                return Err(StsError::new(StatusCode::FORBIDDEN, "unauthorized_client", "client may not revoke subjects"));
            }
            if let Ok(mut r) = self.revoked_subjects.lock() {
                r.insert(sub.clone(), now_unix());
            }
            return Ok(());
        }
        let Some(token) = form.get("token") else {
            return Err(StsError::new(StatusCode::BAD_REQUEST, "invalid_request", "token or sub is required"));
        };
        // RFC 7009: unknown or invalid tokens are not an error.
        if let Ok(claims) = self.verify_subject(token).await {
            if let Some(j) = claims.get("jti").and_then(Value::as_str) {
                if let Ok(mut r) = self.revoked_jti.lock() {
                    r.insert(j.to_string());
                }
            }
        }
        Ok(())
    }

    fn authenticate(&self, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<(String, &ClientDef), StsError> {
        let unauthorized = || StsError::new(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
        let (id, secret) = if let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            let enc = h.strip_prefix("Basic ").ok_or_else(unauthorized)?;
            let raw = base64::engine::general_purpose::STANDARD.decode(enc).map_err(|_| unauthorized())?;
            let s = String::from_utf8(raw).map_err(|_| unauthorized())?;
            let (i, p) = s.split_once(':').ok_or_else(unauthorized)?;
            (i.to_string(), p.to_string())
        } else {
            (form.get("client_id").cloned().ok_or_else(unauthorized)?, form.get("client_secret").cloned().ok_or_else(unauthorized)?)
        };
        let def = self.cfg.clients.get(&id).ok_or_else(unauthorized)?;
        if !constant_time_eq(def.secret.as_bytes(), secret.as_bytes()) {
            return Err(unauthorized());
        }
        Ok((id, def))
    }

    /// Core of the token endpoint; usable without HTTP.
    pub async fn handle(&self, headers: &HeaderMap, form: &HashMap<String, String>) -> Result<Value, StsError> {
        let (client_id, client) = self.authenticate(headers, form)?;
        let grant = form.get("grant_type").map(String::as_str).unwrap_or("");
        let requested_aud = form.get("audience").or_else(|| form.get("resource")).cloned();
        if let Some(aud) = &requested_aud {
            if !client.may_exchange_to.is_empty() && !client.may_exchange_to.contains(aud) {
                return Err(StsError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_target",
                    format!("`{client_id}` may not request audience `{aud}`"),
                ));
            }
        }
        let requested_scopes: Option<Vec<String>> =
            form.get("scope").map(|s| s.split(' ').filter(|x| !x.is_empty()).map(str::to_string).collect());
        let now = now_unix();

        let claims = match grant {
            "client_credentials" => json!({
                "sub": client_id, "azp": client_id, "typ": "Bearer",
                "preferred_username": format!("service-account-{client_id}"),
                "aud": requested_aud.unwrap_or_else(|| self.cfg.issuer.clone()),
                "realm_access": {"roles": client.roles},
                "scope": requested_scopes.unwrap_or_default().join(" "),
                "exp": now + self.cfg.token_ttl_s,
            }),
            TOKEN_EXCHANGE_GRANT => {
                let st = form
                    .get("subject_token")
                    .ok_or_else(|| StsError::new(StatusCode::BAD_REQUEST, "invalid_request", "subject_token is required"))?;
                let subject = self.verify_subject(st).await?;
                let azp = subject.get("azp").and_then(Value::as_str).unwrap_or("").to_string();
                let auds: Vec<String> = match subject.get("aud") {
                    Some(Value::String(s)) => vec![s.clone()],
                    Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
                    _ => vec![],
                };
                let holder = azp == client_id;
                if !holder && !auds.iter().any(|a| client.accept_audiences.contains(a)) {
                    return Err(StsError::new(
                        StatusCode::FORBIDDEN,
                        "unauthorized_client",
                        format!("`{client_id}` may not exchange this token"),
                    ));
                }
                let mut out = match subject {
                    Value::Object(m) => m,
                    _ => Map::new(),
                };
                for k in ["iss", "iat", "jti", "nbf"] {
                    out.remove(k);
                }
                if let Some(target) = form.get("impersonate") {
                    if !client.can_impersonate || !holder {
                        return Err(StsError::new(
                            StatusCode::FORBIDDEN,
                            "unauthorized_client",
                            format!("`{client_id}` may not impersonate"),
                        ));
                    }
                    if form.contains_key("delegate_to") {
                        return Err(StsError::new(StatusCode::BAD_REQUEST, "invalid_request", "impersonate and delegate_to are exclusive"));
                    }
                    let operator = out.get("sub").and_then(Value::as_str).unwrap_or("").to_string();
                    if operator.is_empty() || operator == *target {
                        return Err(StsError::new(StatusCode::BAD_REQUEST, "invalid_request", "invalid impersonation target"));
                    }
                    out = impersonation_claims(&out, target, &operator, form)?;
                }
                if let Some(target) = form.get("delegate_to") {
                    if !holder {
                        return Err(StsError::new(StatusCode::FORBIDDEN, "unauthorized_client", "only the token holder may delegate"));
                    }
                    if let Some(check) = &self.delegation {
                        if !check(&client_id, target) {
                            return Err(StsError::new(
                                StatusCode::FORBIDDEN,
                                "unauthorized_client",
                                format!("`{client_id}` may not delegate to `{target}`"),
                            ));
                        }
                    }
                    let prev_act = out.remove("act");
                    let mut act = json!({"sub": client_id});
                    if let (Some(p), Value::Object(a)) = (prev_act, &mut act) {
                        a.insert("act".into(), p);
                    }
                    out.insert("act".into(), act);
                    out.insert("azp".into(), json!(target));
                }
                if let Some(aud) = requested_aud {
                    out.insert("aud".into(), json!(aud));
                }
                if let Some(req) = requested_scopes {
                    let have: Vec<String> =
                        out.get("scope").and_then(Value::as_str).map(|s| s.split(' ').map(str::to_string).collect()).unwrap_or_default();
                    let narrowed: Vec<String> = req.into_iter().filter(|s| have.contains(s)).collect();
                    out.insert("scope".into(), json!(narrowed.join(" ")));
                }
                let sub_exp = out.get("exp").and_then(Value::as_i64).unwrap_or(now);
                out.insert("exp".into(), json!(sub_exp.min(now + self.cfg.token_ttl_s)));
                Value::Object(out)
            }
            other => {
                return Err(StsError::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", format!("grant `{other}` is not supported")))
            }
        };
        let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(now);
        let token = self.issue(claims).map_err(|e| StsError::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", e))?;
        Ok(json!({
            "access_token": token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": (exp - now).max(0),
        }))
    }
}

/// Claims of a "test as user" token: the target's roles and attributes as supplied by the
/// (trusted) client from its directory, the operator recorded, nothing of the operator's rights.
fn impersonation_claims(
    operator_claims: &Map<String, Value>,
    target: &str,
    operator: &str,
    form: &HashMap<String, String>,
) -> Result<Map<String, Value>, StsError> {
    const RESERVED: &[&str] =
        &["sub", "azp", "aud", "exp", "iss", "iat", "nbf", "jti", "act", "typ", "scope", "realm_access", "warden_impersonation"];
    let roles: Vec<&str> = form.get("roles").map(|r| r.split(' ').filter(|x| !x.is_empty()).collect()).unwrap_or_default();
    let mut out = Map::new();
    if let Some(Value::Object(extra)) = form
        .get("claims")
        .map(|c| serde_json::from_str::<Value>(c))
        .transpose()
        .map_err(|e| StsError::new(StatusCode::BAD_REQUEST, "invalid_request", format!("`claims` must be a JSON object: {e}")))?
    {
        for (k, v) in extra {
            if RESERVED.contains(&k.as_str()) {
                return Err(StsError::new(StatusCode::BAD_REQUEST, "invalid_request", format!("`claims` may not set `{k}`")));
            }
            out.insert(k, v);
        }
    }
    for k in ["azp", "aud", "exp", "typ", "scope"] {
        if let Some(v) = operator_claims.get(k) {
            out.insert(k.into(), v.clone());
        }
    }
    out.insert("sub".into(), json!(target));
    out.insert("preferred_username".into(), json!(target));
    out.insert("realm_access".into(), json!({ "roles": roles }));
    out.insert("warden_impersonation".into(), json!({ "by": operator }));
    Ok(out)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn discovery(State(sts): State<Arc<Sts>>) -> Json<Value> {
    let iss = sts.cfg.issuer.trim_end_matches('/');
    Json(json!({
        "issuer": sts.cfg.issuer,
        "jwks_uri": format!("{iss}/jwks"),
        "token_endpoint": format!("{iss}/token"),
        "grant_types_supported": ["client_credentials", TOKEN_EXCHANGE_GRANT],
        "introspection_endpoint": format!("{iss}/introspect"),
        "revocation_endpoint": format!("{iss}/revoke"),
        "id_token_signing_alg_values_supported": ["ES256"],
    }))
}

async fn jwks(State(sts): State<Arc<Sts>>) -> Json<JwkSet> {
    Json(sts.jwks())
}

async fn introspect_endpoint(State(sts): State<Arc<Sts>>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    match sts.introspect(&headers, &form).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn revoke_endpoint(State(sts): State<Arc<Sts>>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    match sts.revoke(&headers, &form).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

async fn token(State(sts): State<Arc<Sts>>, headers: HeaderMap, Form(form): Form<HashMap<String, String>>) -> Response {
    match sts.handle(&headers, &form).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => e.into_response(),
    }
}
