//! How the gateway authenticates to upstreams. The client's token is **never** passed through.

use std::collections::HashMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub enum UpstreamAuth {
    None,
    /// A fixed token, e.g. for a third-party API key.
    Static(String),
    /// The gateway's own service account.
    ClientCredentials { token_url: String, client_id: String, secret: String, audience: Option<String>, scope: Option<String> },
    /// RFC 8693: exchange the user's token for one scoped to this upstream (keeps `sub` and `act`).
    TokenExchange { token_url: String, client_id: String, secret: String, audience: String, scope: Option<String> },
}

#[derive(Default)]
pub struct TokenCache(Mutex<HashMap<String, (String, i64)>>);

impl UpstreamAuth {
    /// The credential to present to the upstream for a request carrying `subject_token`.
    pub async fn credential(
        &self,
        http: &reqwest::Client,
        cache: &TokenCache,
        subject_token: &str,
        now: i64,
    ) -> Result<Option<String>, String> {
        let (key, form): (String, Vec<(&str, String)>) = match self {
            UpstreamAuth::None => return Ok(None),
            UpstreamAuth::Static(t) => return Ok(Some(t.clone())),
            UpstreamAuth::ClientCredentials { token_url, client_id, secret, audience, scope } => {
                let mut f = vec![
                    ("grant_type", "client_credentials".to_string()),
                    ("client_id", client_id.clone()),
                    ("client_secret", secret.clone()),
                ];
                if let Some(a) = audience {
                    f.push(("audience", a.clone()));
                }
                if let Some(s) = scope {
                    f.push(("scope", s.clone()));
                }
                (format!("cc|{token_url}|{client_id}|{audience:?}"), f)
            }
            UpstreamAuth::TokenExchange { token_url, client_id, secret, audience, scope } => {
                let mut f = vec![
                    ("grant_type", agent_scope_identity::TOKEN_EXCHANGE_GRANT.to_string()),
                    ("client_id", client_id.clone()),
                    ("client_secret", secret.clone()),
                    ("subject_token", subject_token.to_string()),
                    ("subject_token_type", "urn:ietf:params:oauth:token-type:access_token".to_string()),
                    ("audience", audience.clone()),
                ];
                if let Some(s) = scope {
                    f.push(("scope", s.clone()));
                }
                let h = hex::encode(Sha256::digest(subject_token.as_bytes()));
                (format!("tx|{token_url}|{audience}|{h}"), f)
            }
        };
        if let Some((tok, exp)) = cache.0.lock().await.get(&key) {
            if *exp > now + 30 {
                return Ok(Some(tok.clone()));
            }
        }
        let url = match self {
            UpstreamAuth::ClientCredentials { token_url, .. } | UpstreamAuth::TokenExchange { token_url, .. } => token_url,
            _ => return Ok(None),
        };
        let resp = http.post(url).form(&form).send().await.map_err(|e| format!("token endpoint: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            return Err(format!("token endpoint returned {status}: {}", body.get("error").and_then(Value::as_str).unwrap_or("")));
        }
        let body: Value = resp.json().await.map_err(|e| e.to_string())?;
        let token = body.get("access_token").and_then(Value::as_str).ok_or("no access_token in response")?.to_string();
        let exp = now + body.get("expires_in").and_then(Value::as_i64).unwrap_or(60);
        cache.0.lock().await.insert(key, (token.clone(), exp));
        Ok(Some(token))
    }
}
