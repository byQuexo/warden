//! Attribute resolvers enrich a principal before the (pure) check, e.g. from an HR system,
//! LDAP or a relationship service. They run outside the core because they do I/O.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::Mutex;
use warden_core::{AttrValue, Attrs, Principal};

#[async_trait]
pub trait AttributeResolver: Send + Sync {
    /// Attributes for this principal. An error makes the caller deny (`attrs.unavailable`).
    async fn resolve(&self, principal: &Principal) -> Result<Attrs, String>;
}

/// Merge resolved attributes into the principal. The resolver is authoritative and wins on conflicts.
pub async fn enrich(resolver: &dyn AttributeResolver, mut p: Principal) -> Result<Principal, String> {
    let attrs = resolver.resolve(&p).await?;
    p.subject.attrs.extend(attrs);
    Ok(p)
}

/// Fixed attributes per subject id, e.g. from a YAML file.
pub struct StaticResolver(pub BTreeMap<String, Attrs>);

impl StaticResolver {
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        serde_norway::from_str(s).map(StaticResolver).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl AttributeResolver for StaticResolver {
    async fn resolve(&self, p: &Principal) -> Result<Attrs, String> {
        Ok(self.0.get(&p.subject.id).cloned().unwrap_or_default())
    }
}

/// `GET <url with {subject.id}>` → JSON object of attributes, cached per subject.
pub struct HttpResolver {
    url_template: String,
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<String, (Instant, Attrs)>>,
}

impl HttpResolver {
    pub fn new(url_template: impl Into<String>, ttl: Duration) -> Self {
        Self {
            url_template: url_template.into(),
            http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap_or_default(),
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }
}

fn encode_component(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[async_trait]
impl AttributeResolver for HttpResolver {
    async fn resolve(&self, p: &Principal) -> Result<Attrs, String> {
        if let Some((at, a)) = self.cache.lock().await.get(&p.subject.id) {
            if at.elapsed() < self.ttl {
                return Ok(a.clone());
            }
        }
        let url = self.url_template.replace("{subject.id}", &encode_component(&p.subject.id));
        let r = self.http.get(&url).send().await.map_err(|e| e.to_string())?;
        if !r.status().is_success() {
            return Err(format!("attribute service returned HTTP {}", r.status()));
        }
        let v: Value = r.json().await.map_err(|e| e.to_string())?;
        let Value::Object(m) = v else { return Err("attribute service must return an object".into()) };
        let mut attrs = Attrs::new();
        for (k, v) in m {
            let a = match v {
                Value::String(s) => AttrValue::String(s),
                Value::Bool(b) => AttrValue::Bool(b),
                Value::Number(n) => AttrValue::Number(n.as_f64().unwrap_or(0.0)),
                Value::Array(a) => AttrValue::List(a.into_iter().filter_map(|x| x.as_str().map(str::to_string)).collect()),
                _ => continue,
            };
            attrs.insert(k, a);
        }
        self.cache.lock().await.insert(p.subject.id.clone(), (Instant::now(), attrs.clone()));
        Ok(attrs)
    }
}
