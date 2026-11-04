//! WebAssembly bindings. Values cross the boundary as JSON strings so that the TypeScript
//! side gets exactly the same strict parsing (duplicate keys, depth, size) as Rust.

use serde_json::{json, Value};
use warden_core::json::{parse_strict, Limits};
use warden_core::{principal_from_claims, Action, Context, Engine, IdentityConfig, Principal};
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, s: &str) -> Result<T, String> {
    let v = parse_strict(s, Limits { max_bytes: 1 << 20, max_depth: 64 }).map_err(|e| format!("{what}: {e}"))?;
    serde_json::from_value(v).map_err(|e| format!("{what}: {e}"))
}

#[wasm_bindgen]
pub struct Scope {
    engine: Engine,
}

#[wasm_bindgen]
impl Scope {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_yaml: &str, catalog_yaml: &str, lock_json: Option<String>) -> Result<Scope, JsValue> {
        let mut b = Engine::builder().policy_yaml(policy_yaml).catalog_yaml(catalog_yaml);
        if let Some(l) = lock_json {
            b = b.lock_json(&l);
        }
        b.build().map(|engine| Scope { engine }).map_err(err)
    }

    /// Decide. `action_json` is parsed strictly; a malformed action is a `deny`, not an exception.
    pub fn check(&self, principal_json: &str, action_json: &str, context_json: Option<String>) -> Result<String, JsValue> {
        let p: Principal = parse("principal", principal_json).map_err(err)?;
        let ctx: Context = match context_json {
            Some(c) => parse("context", &c).map_err(err)?,
            None => Context::default(),
        };
        let d = match parse::<Action>("action", action_json) {
            Ok(a) => serde_json::to_value(self.engine.check(&p, &a, &ctx)).map_err(err)?,
            Err(e) => json!({
                "effect": "deny", "rule": "normalize.args", "reason": e,
                "model_message": "This action is not permitted.", "trace": [], "policy_version": self.engine.version()
            }),
        };
        Ok(d.to_string())
    }

    pub fn visible(&self, principal_json: &str, action_json: &str, context_json: Option<String>) -> Result<bool, JsValue> {
        let p: Principal = parse("principal", principal_json).map_err(err)?;
        let ctx: Context = match context_json {
            Some(c) => parse("context", &c).map_err(err)?,
            None => Context::default(),
        };
        Ok(match parse::<Action>("action", action_json) {
            Ok(a) => self.engine.visible(&p, &a, &ctx),
            Err(_) => false,
        })
    }

    pub fn version(&self) -> String {
        self.engine.version().to_string()
    }

    pub fn warnings(&self) -> String {
        serde_json::to_string(self.engine.warnings()).unwrap_or_default()
    }

    #[wasm_bindgen(js_name = effectiveScopes)]
    pub fn effective_scopes(&self, principal_json: &str) -> Result<String, JsValue> {
        let p: Principal = parse("principal", principal_json).map_err(err)?;
        Ok(json!(self.engine.effective_scopes(&p)).to_string())
    }
}

/// Map verified claims to a principal. Returns `{"ok": principal}` or `{"error": {code, message}}`.
#[wasm_bindgen(js_name = principalFromClaims)]
pub fn principal_from_claims_js(identity_yaml: &str, claims_json: &str, now: f64) -> Result<String, JsValue> {
    let cfg = IdentityConfig::from_yaml_str(identity_yaml).map_err(err)?;
    let claims: Value = parse("claims", claims_json).map_err(err)?;
    Ok(match principal_from_claims(&claims, &cfg, now as i64) {
        Ok(p) => json!({"ok": p}),
        Err(e) => json!({"error": {"code": e.code(), "message": e.to_string()}}),
    }
    .to_string())
}

/// Validate an identity config and list its issuers (used by the TS verifier).
#[wasm_bindgen(js_name = identityIssuers)]
pub fn identity_issuers(identity_yaml: &str) -> Result<String, JsValue> {
    let cfg = IdentityConfig::from_yaml_str(identity_yaml).map_err(err)?;
    Ok(json!(cfg
        .issuers
        .iter()
        .map(|i| json!({"issuer": i.issuer, "audience": i.audience, "algorithms": i.algorithms, "jwks_uri": i.jwks_uri}))
        .collect::<Vec<_>>())
    .to_string())
}

#[wasm_bindgen]
pub fn lint(policy_yaml: &str, catalog_yaml: &str) -> Result<String, JsValue> {
    let policy = warden_core::Policy::from_yaml_str(policy_yaml).map_err(err)?;
    let catalog = warden_core::Catalog::from_yaml_str(catalog_yaml).map_err(err)?;
    let (rules, mut f) = warden_core::engine::compile_rules(&policy);
    f.extend(warden_core::lint::lint(&policy, &catalog, &rules, &Default::default()));
    Ok(serde_json::to_string(&f).unwrap_or_default())
}
