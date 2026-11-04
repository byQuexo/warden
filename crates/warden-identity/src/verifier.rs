use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use tokio::sync::Mutex;
use warden_core::claims::IssuerConfig;
use warden_core::{principal_from_claims, IdentityConfig, Principal, TokenError};

struct KeyCache {
    keys: JwkSet,
    last_fetch: Option<Instant>,
}

/// Verifies JWT signatures for the issuers of an [`IdentityConfig`].
///
/// Only the signature, algorithm and key id are checked here; issuer, audience, expiry,
/// token type and claim mapping are the job of the pure core so that Rust and TypeScript
/// behave identically.
pub struct Verifier {
    cfg: IdentityConfig,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, KeyCache>>,
    static_keys: HashMap<String, JwkSet>,
    refresh_interval: Duration,
}

impl Verifier {
    pub fn new(cfg: IdentityConfig) -> Self {
        Self {
            cfg,
            http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default(),
            cache: Mutex::new(HashMap::new()),
            static_keys: HashMap::new(),
            refresh_interval: Duration::from_secs(60),
        }
    }

    /// Use a fixed key set for an issuer instead of fetching (tests, air-gapped setups).
    pub fn with_static_jwks(mut self, issuer: &str, keys: JwkSet) -> Self {
        self.static_keys.insert(issuer.to_string(), keys);
        self
    }

    /// Minimum time between two JWKS fetches for the same issuer (kid-flood protection).
    pub fn with_refresh_interval(mut self, d: Duration) -> Self {
        self.refresh_interval = d;
        self
    }

    pub fn config(&self) -> &IdentityConfig {
        &self.cfg
    }

    /// Full verification: signature + claims → principal.
    pub async fn verify(&self, token: &str, now: i64) -> Result<Principal, TokenError> {
        let (claims, _) = self.verify_signature(token).await?;
        principal_from_claims(&claims, &self.cfg, now)
    }

    /// Signature-only verification. Returns the claims and the issuer config.
    pub async fn verify_signature(&self, token: &str) -> Result<(Value, &IssuerConfig), TokenError> {
        let header = decode_header(token).map_err(|e| TokenError::Invalid(format!("header: {e}")))?;
        let iss = peek_issuer(token)?;
        let ic = self.cfg.issuer(&iss).ok_or_else(|| TokenError::UnknownIssuer(iss.clone()))?;
        let alg_name = alg_name(header.alg).ok_or_else(|| TokenError::Invalid(format!("algorithm {:?} is not allowed", header.alg)))?;
        if !ic.algorithms.iter().any(|a| a == alg_name) {
            return Err(TokenError::Invalid(format!("algorithm {alg_name} is not allowed for this issuer")));
        }
        let kid = header.kid.ok_or_else(|| TokenError::Invalid("missing kid".into()))?;
        let jwk = self.key(ic, &kid).await?;
        if !key_matches_alg(&jwk, header.alg) {
            return Err(TokenError::Invalid("key type does not match algorithm".into()));
        }
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| TokenError::Invalid(format!("jwk: {e}")))?;
        let mut v = Validation::new(header.alg);
        v.validate_exp = false;
        v.validate_nbf = false;
        v.validate_aud = false;
        v.required_spec_claims.clear();
        let data = decode::<Value>(token, &key, &v).map_err(|e| TokenError::Invalid(e.to_string()))?;
        Ok((data.claims, ic))
    }

    async fn key(&self, ic: &IssuerConfig, kid: &str) -> Result<Jwk, TokenError> {
        if let Some(set) = self.static_keys.get(&ic.issuer) {
            return set.find(kid).cloned().ok_or_else(|| TokenError::Invalid(format!("unknown kid `{kid}`")));
        }
        let mut cache = self.cache.lock().await;
        let entry = cache.entry(ic.issuer.clone()).or_insert(KeyCache { keys: JwkSet { keys: vec![] }, last_fetch: None });
        if let Some(k) = entry.keys.find(kid) {
            return Ok(k.clone());
        }
        // Unknown kid: refresh at most once per interval, otherwise reject.
        if entry.last_fetch.is_some_and(|t| t.elapsed() < self.refresh_interval) {
            return Err(TokenError::Invalid(format!("unknown kid `{kid}`")));
        }
        entry.last_fetch = Some(Instant::now());
        let keys = self.fetch_jwks(ic).await?;
        entry.keys = keys;
        entry.keys.find(kid).cloned().ok_or_else(|| TokenError::Invalid(format!("unknown kid `{kid}`")))
    }

    async fn fetch_jwks(&self, ic: &IssuerConfig) -> Result<JwkSet, TokenError> {
        let uri = match &ic.jwks_uri {
            Some(u) => u.clone(),
            None => {
                let url = format!("{}/.well-known/openid-configuration", ic.issuer.trim_end_matches('/'));
                let doc: Value = self.get_json(&url).await?;
                doc.get("jwks_uri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| TokenError::Invalid("discovery document has no jwks_uri".into()))?
                    .to_string()
            }
        };
        let v = self.get_json(&uri).await?;
        serde_json::from_value(v).map_err(|e| TokenError::Invalid(format!("jwks: {e}")))
    }

    async fn get_json(&self, url: &str) -> Result<Value, TokenError> {
        let r = self.http.get(url).send().await.map_err(|e| TokenError::Invalid(format!("fetch {url}: {e}")))?;
        if !r.status().is_success() {
            return Err(TokenError::Invalid(format!("fetch {url}: HTTP {}", r.status())));
        }
        r.json().await.map_err(|e| TokenError::Invalid(format!("fetch {url}: {e}")))
    }
}

fn alg_name(a: Algorithm) -> Option<&'static str> {
    match a {
        Algorithm::RS256 => Some("RS256"),
        Algorithm::ES256 => Some("ES256"),
        Algorithm::EdDSA => Some("EdDSA"),
        _ => None,
    }
}

fn key_matches_alg(jwk: &Jwk, alg: Algorithm) -> bool {
    match (&jwk.algorithm, alg) {
        (AlgorithmParameters::RSA(_), Algorithm::RS256) => true,
        (AlgorithmParameters::EllipticCurve(p), Algorithm::ES256) => p.curve == EllipticCurve::P256,
        (AlgorithmParameters::OctetKeyPair(p), Algorithm::EdDSA) => p.curve == EllipticCurve::Ed25519,
        _ => false,
    }
}

/// Read `iss` from the unverified payload, only to pick the key set. The issuer is checked
/// again after the signature has been verified.
fn peek_issuer(token: &str) -> Result<String, TokenError> {
    let payload = token.split('.').nth(1).ok_or_else(|| TokenError::Invalid("not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Invalid("payload is not base64url".into()))?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|_| TokenError::Invalid("payload is not JSON".into()))?;
    v.get("iss").and_then(Value::as_str).map(str::to_string).ok_or_else(|| TokenError::MissingClaim("iss".into()))
}
