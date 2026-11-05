//! Verified token claims → [`Principal`].
//!
//! Signature verification needs keys and network access, so it lives outside the core
//! (`warden-identity` in Rust, `jose` in TypeScript). Everything *after* the signature
//! — issuer, audience, expiry, token type, delegation chain and the mapping of claims to
//! roles, scopes and attributes — happens here, as a pure function of `(claims, config, now)`.
//! Rust and TypeScript therefore share one implementation and one set of test vectors.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{AttrValue, Attrs, Principal, Subject, SubjectKind};

pub const ALLOWED_ALGORITHMS: &[&str] = &["RS256", "ES256", "EdDSA"];

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub version: u32,
    pub issuers: Vec<IssuerConfig>,
    /// Issuers trusted to put an `act` (delegation) chain into a token.
    #[serde(default)]
    pub delegation_issuers: Vec<String>,
    #[serde(default)]
    pub scope_claim: ScopeClaim,
    #[serde(default = "default_skew")]
    pub clock_skew_s: i64,
}

fn default_skew() -> i64 {
    30
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ScopeClaim {
    /// Token scopes are intersected with role and agent scopes (missing claim = no scopes).
    #[default]
    Required,
    /// Token scopes are not used.
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub issuer: String,
    pub audience: String,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// Explicit JWKS URI; otherwise OIDC discovery is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    pub mapping: MappingRef,
    /// RFC 7662 token introspection: revoked tokens are rejected immediately, and opaque
    /// (non-JWT) tokens are accepted. Checked on every request (optionally cached).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introspection: Option<IntrospectionConfig>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct IntrospectionConfig {
    pub endpoint: String,
    pub client_id: String,
    /// Environment variable holding the client secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_env: Option<String>,
    /// Cache positive answers for this many seconds (0 = ask every time).
    #[serde(default)]
    pub cache_s: u64,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into(), "ES256".into()]
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // config type, built once
pub enum MappingRef {
    Preset {
        preset: String,
        #[serde(default)]
        attrs: BTreeMap<String, ListSpec>,
    },
    Inline(Mapping),
}

/// Declarative claim mapping using JSON Pointers (RFC 6901).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub subject: PathSpec,
    pub agent: PathSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<ListSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<ListSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_type: Option<ClaimTest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_if: Option<ClaimTest>,
    #[serde(default)]
    pub attrs: BTreeMap<String, ListSpec>,
}

/// One pointer, or a list of pointers where the first present one wins.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum PathSpec {
    One(String),
    FirstOf(Vec<String>),
}

impl PathSpec {
    fn lookup<'a>(&self, claims: &'a Value) -> Option<&'a Value> {
        match self {
            PathSpec::One(p) => claims.pointer(p),
            PathSpec::FirstOf(ps) => ps.iter().find_map(|p| claims.pointer(p)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum ListSpec {
    Path(String),
    Split { path: String, split: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ClaimTest {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Holds if the claim equals the claim at this other pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_as: Option<String>,
}

impl ClaimTest {
    fn holds(&self, claims: &Value) -> bool {
        let Some(v) = claims.pointer(&self.path).and_then(Value::as_str) else {
            return false;
        };
        if let Some(e) = &self.equals {
            return v == e;
        }
        if let Some(p) = &self.prefix {
            return v.starts_with(p.as_str());
        }
        if let Some(other) = &self.same_as {
            return claims.pointer(other).and_then(Value::as_str) == Some(v);
        }
        true
    }
}

/// Built-in presets, shipped as YAML so new ones need no code.
pub const PRESETS: &[(&str, &str)] = &[
    ("keycloak", include_str!("../presets/keycloak.yaml")),
    ("auth0", include_str!("../presets/auth0.yaml")),
    ("entra-id", include_str!("../presets/entra-id.yaml")),
    ("okta", include_str!("../presets/okta.yaml")),
    ("generic-oidc", include_str!("../presets/generic-oidc.yaml")),
];

pub fn preset(name: &str) -> Option<Result<Mapping, String>> {
    PRESETS.iter().find(|(n, _)| *n == name).map(|(_, y)| serde_norway::from_str(y).map_err(|e| format!("preset `{name}`: {e}")))
}

impl MappingRef {
    pub fn resolve(&self) -> Result<Mapping, String> {
        match self {
            MappingRef::Inline(m) => Ok(m.clone()),
            MappingRef::Preset { preset: name, attrs } => {
                let mut m = preset(name).ok_or_else(|| format!("unknown mapping preset `{name}`"))??;
                m.attrs.extend(attrs.clone());
                Ok(m)
            }
        }
    }
}

impl IdentityConfig {
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        let c: IdentityConfig = serde_norway::from_str(s).map_err(|e| e.to_string())?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!("unsupported identity version {}", self.version));
        }
        if self.issuers.is_empty() {
            return Err("at least one issuer is required".into());
        }
        for i in &self.issuers {
            if i.issuer.is_empty() || i.audience.is_empty() {
                return Err("issuer and audience must not be empty".into());
            }
            for a in &i.algorithms {
                if !ALLOWED_ALGORITHMS.contains(&a.as_str()) {
                    return Err(format!(
                        "issuer `{}`: algorithm `{a}` is not allowed (allowed: {})",
                        i.issuer,
                        ALLOWED_ALGORITHMS.join(", ")
                    ));
                }
            }
            i.mapping.resolve()?;
        }
        Ok(())
    }

    pub fn issuer(&self, iss: &str) -> Option<&IssuerConfig> {
        self.issuers.iter().find(|i| i.issuer == iss)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "detail", rename_all = "snake_case")]
pub enum TokenError {
    #[error("token issuer `{0}` is not trusted")]
    UnknownIssuer(String),
    #[error("token audience does not include `{0}`")]
    Audience(String),
    #[error("token expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("not an access token")]
    TokenType,
    #[error("required claim `{0}` is missing or malformed")]
    MissingClaim(String),
    #[error("issuer `{0}` may not issue delegation chains")]
    DelegationIssuer(String),
    #[error("mapping error: {0}")]
    Mapping(String),
    #[error("signature or format invalid: {0}")]
    Invalid(String),
    #[error("token was revoked or is no longer active")]
    Revoked,
}

impl TokenError {
    pub fn code(&self) -> &'static str {
        match self {
            TokenError::UnknownIssuer(_) => "unknown_issuer",
            TokenError::Audience(_) => "audience",
            TokenError::Expired => "expired",
            TokenError::NotYetValid => "not_yet_valid",
            TokenError::TokenType => "token_type",
            TokenError::MissingClaim(_) => "missing_claim",
            TokenError::DelegationIssuer(_) => "delegation_issuer",
            TokenError::Mapping(_) => "mapping",
            TokenError::Invalid(_) => "invalid",
            TokenError::Revoked => "revoked",
        }
    }
}

fn list(claims: &Value, spec: &ListSpec) -> Option<Vec<String>> {
    match spec {
        ListSpec::Path(p) => match claims.pointer(p)? {
            Value::Array(a) => Some(a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
            Value::String(s) => Some(vec![s.clone()]),
            _ => None,
        },
        ListSpec::Split { path, split } => {
            let s = claims.pointer(path)?.as_str()?;
            Some(s.split(split.as_str()).filter(|x| !x.is_empty()).map(str::to_string).collect())
        }
    }
}

fn attr(claims: &Value, spec: &ListSpec) -> Option<AttrValue> {
    match spec {
        ListSpec::Split { .. } => list(claims, spec).map(AttrValue::List),
        ListSpec::Path(p) => match claims.pointer(p)? {
            Value::String(s) => Some(AttrValue::String(s.clone())),
            Value::Bool(b) => Some(AttrValue::Bool(*b)),
            Value::Number(n) => n.as_f64().map(AttrValue::Number),
            Value::Array(a) if a.iter().all(Value::is_string) => {
                Some(AttrValue::List(a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()))
            }
            _ => None,
        },
    }
}

/// RFC 8693 `act` is nested with the most recent actor outermost; we return oldest first.
fn act_chain(v: &Value) -> Result<Vec<String>, TokenError> {
    let mut out = Vec::new();
    let mut cur = Some(v);
    while let Some(node) = cur {
        let sub = node.get("sub").and_then(Value::as_str).ok_or_else(|| TokenError::MissingClaim("act.sub".into()))?;
        out.push(sub.to_string());
        if out.len() > 16 {
            return Err(TokenError::MissingClaim("act (chain too long)".into()));
        }
        cur = node.get("act");
    }
    out.reverse();
    Ok(out)
}

/// Map verified claims to a principal. `now` is unix seconds.
pub fn principal_from_claims(claims: &Value, cfg: &IdentityConfig, now: i64) -> Result<Principal, TokenError> {
    let iss = claims.get("iss").and_then(Value::as_str).ok_or_else(|| TokenError::MissingClaim("iss".into()))?;
    let ic = cfg.issuer(iss).ok_or_else(|| TokenError::UnknownIssuer(iss.to_string()))?;

    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == &ic.audience,
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(ic.audience.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(TokenError::Audience(ic.audience.clone()));
    }
    let exp = claims.get("exp").and_then(Value::as_i64).ok_or_else(|| TokenError::MissingClaim("exp".into()))?;
    if now > exp + cfg.clock_skew_s {
        return Err(TokenError::Expired);
    }
    if let Some(nbf) = claims.get("nbf").and_then(Value::as_i64) {
        if now + cfg.clock_skew_s < nbf {
            return Err(TokenError::NotYetValid);
        }
    }

    let m = ic.mapping.resolve().map_err(TokenError::Mapping)?;
    if let Some(tt) = &m.token_type {
        if !tt.holds(claims) {
            return Err(TokenError::TokenType);
        }
    }
    let subject_id = m.subject.lookup(claims).and_then(Value::as_str).ok_or_else(|| TokenError::MissingClaim("subject".into()))?;
    let agent = m.agent.lookup(claims).and_then(Value::as_str).ok_or_else(|| TokenError::MissingClaim("agent".into()))?;

    let roles: BTreeSet<String> = m.roles.as_ref().and_then(|r| list(claims, r)).unwrap_or_default().into_iter().collect();
    let token_scopes = match cfg.scope_claim {
        ScopeClaim::Ignore => None,
        ScopeClaim::Required => Some(m.scopes.as_ref().and_then(|s| list(claims, s)).unwrap_or_default().into_iter().collect()),
    };

    let act = match m.act.as_ref().and_then(|p| claims.pointer(p)) {
        None | Some(Value::Null) => Vec::new(),
        Some(v) => {
            if !cfg.delegation_issuers.iter().any(|d| d == iss) {
                return Err(TokenError::DelegationIssuer(iss.to_string()));
            }
            act_chain(v)?
        }
    };

    // Set by a trusted token service for "test as user"; same trust rule as `act`.
    let impersonated_by = match claims.pointer("/warden_impersonation/by") {
        None | Some(Value::Null) => None,
        Some(Value::String(by)) if !by.is_empty() => {
            if !cfg.delegation_issuers.iter().any(|d| d == iss) {
                return Err(TokenError::DelegationIssuer(iss.to_string()));
            }
            Some(by.clone())
        }
        Some(_) => return Err(TokenError::MissingClaim("warden_impersonation.by".into())),
    };

    let mut attrs = Attrs::new();
    for (k, spec) in &m.attrs {
        if let Some(v) = attr(claims, spec) {
            attrs.insert(k.clone(), v);
        }
    }
    let kind = if m.service_if.as_ref().is_some_and(|t| t.holds(claims)) { SubjectKind::Service } else { SubjectKind::User };

    Ok(Principal {
        subject: Subject { id: subject_id.to_string(), kind, roles, attrs },
        agent: agent.to_string(),
        act,
        token_scopes,
        expires_at: Some(exp),
        issuer: Some(iss.to_string()),
        impersonated_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> IdentityConfig {
        IdentityConfig::from_yaml_str(
            r#"
version: 1
issuers:
  - issuer: https://kc/realms/acme
    audience: https://gw/mcp
    mapping: { preset: keycloak, attrs: { org_unit: /org_unit, tenants: /tenants } }
delegation_issuers: [https://sts]
"#,
        )
        .unwrap()
    }

    fn claims() -> Value {
        json!({
            "iss": "https://kc/realms/acme", "aud": ["https://gw/mcp", "account"], "exp": 2000, "typ": "Bearer",
            "sub": "u-1", "azp": "acme-bot", "realm_access": {"roles": ["hr-lead"]}, "scope": "openid hr:read",
            "org_unit": "hr", "tenants": ["dach"]
        })
    }

    #[test]
    fn maps_keycloak_claims() {
        let p = principal_from_claims(&claims(), &cfg(), 1000).unwrap();
        assert_eq!(p.subject.id, "u-1");
        assert_eq!(p.agent, "acme-bot");
        assert!(p.subject.roles.contains("hr-lead"));
        assert!(p.token_scopes.as_ref().unwrap().contains("hr:read"));
        assert_eq!(p.subject.attrs.get("tenants"), Some(&AttrValue::List(vec!["dach".into()])));
    }

    #[test]
    fn rejects_bad_tokens() {
        let c = cfg();
        let mut x = claims();
        x["aud"] = json!("other");
        assert_eq!(principal_from_claims(&x, &c, 1000), Err(TokenError::Audience("https://gw/mcp".into())));
        assert_eq!(principal_from_claims(&claims(), &c, 3000), Err(TokenError::Expired));
        let mut id_token = claims();
        id_token["typ"] = json!("ID");
        assert_eq!(principal_from_claims(&id_token, &c, 1000), Err(TokenError::TokenType));
        let mut act = claims();
        act["act"] = json!({"sub": "acme-research"});
        assert!(matches!(principal_from_claims(&act, &c, 1000), Err(TokenError::DelegationIssuer(_))));
    }

    #[test]
    fn act_chain_is_oldest_first() {
        let v = json!({"sub": "research", "act": {"sub": "bot"}});
        assert_eq!(act_chain(&v).unwrap(), vec!["bot".to_string(), "research".to_string()]);
    }

    #[test]
    fn rejects_weak_algorithms() {
        let y = "version: 1\nissuers:\n  - { issuer: a, audience: b, algorithms: [HS256], mapping: { preset: keycloak } }";
        assert!(IdentityConfig::from_yaml_str(y).is_err());
    }

    #[test]
    fn all_presets_parse() {
        for (n, _) in PRESETS {
            preset(n).unwrap().unwrap();
        }
    }
}
