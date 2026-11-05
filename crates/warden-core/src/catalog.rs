//! The catalog: every action that exists, which scopes it needs and how risky it is.
//! Anything not in the catalog (or tagged with no scopes) is denied.
//!
//! ```yaml
//! version: 1
//! tool:
//!   crm.update_deal: { scopes: [crm:write], sensitivity: write }
//!   "*.delete_*":    { scopes: [admin], sensitivity: write, tags: [destructive] }
//! resource:
//!   "docs://hr/**":  { scopes: [docs:hr] }
//! x-payment:
//!   _normalize: name
//!   payments.transfer: { scopes: [payments:write], sensitivity: write }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::glob;
use crate::model::ActionKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    #[default]
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizeMode {
    Name,
    Uri,
}

/// One catalog entry as written in YAML.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Write argument values in clear text to the audit log (never for `pii`-tagged entries).
    #[serde(default)]
    pub audit_args: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KindSection {
    pub normalize: NormalizeMode,
    /// Pattern → entry, in file order (BTreeMap gives deterministic order).
    pub entries: BTreeMap<String, CatalogEntry>,
}

/// All matching entries merged: scopes and tags are unioned, the highest sensitivity wins.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Resolved {
    pub scopes: BTreeSet<String>,
    pub sensitivity: Sensitivity,
    pub tags: BTreeSet<String>,
    pub audit_args: bool,
    pub patterns: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Catalog {
    pub version: u32,
    pub kinds: BTreeMap<ActionKind, KindSection>,
}

impl Catalog {
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        let raw: BTreeMap<String, Value> = serde_norway::from_str(s).map_err(|e| e.to_string())?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: BTreeMap<String, Value>) -> Result<Self, String> {
        let mut version = None;
        let mut kinds = BTreeMap::new();
        for (key, value) in raw {
            if key == "version" {
                version = Some(value.as_u64().ok_or("`version` must be an integer")? as u32);
                continue;
            }
            let kind: ActionKind = key.parse()?;
            let Value::Object(map) = value else {
                return Err(format!("section `{key}` must be a mapping"));
            };
            let mut normalize = default_normalize(&kind);
            let mut entries = BTreeMap::new();
            for (pattern, entry) in map {
                if pattern == "_normalize" {
                    normalize = serde_json::from_value(entry).map_err(|_| format!("`{key}._normalize` must be `name` or `uri`"))?;
                    continue;
                }
                let e: CatalogEntry = serde_json::from_value(entry).map_err(|e| format!("`{key}.{pattern}`: {e}"))?;
                entries.insert(pattern, e);
            }
            kinds.insert(kind, KindSection { normalize, entries });
        }
        match version {
            Some(1) => Ok(Self { version: 1, kinds }),
            Some(v) => Err(format!("unsupported catalog version {v} (expected 1)")),
            None => Err("catalog is missing `version: 1`".into()),
        }
    }

    pub fn normalize_mode(&self, kind: &ActionKind) -> NormalizeMode {
        self.kinds.get(kind).map(|s| s.normalize).unwrap_or_else(|| default_normalize(kind))
    }

    /// Merge all entries whose pattern matches `name` (already normalized).
    pub fn resolve(&self, kind: &ActionKind, name: &str) -> Option<Resolved> {
        let section = self.kinds.get(kind)?;
        let sep = glob::separator_for_uri(section.normalize == NormalizeMode::Uri);
        let mut out: Option<Resolved> = None;
        for (pattern, e) in &section.entries {
            if !glob::matches(pattern, name, sep) {
                continue;
            }
            let r = out.get_or_insert_with(|| Resolved {
                scopes: BTreeSet::new(),
                sensitivity: Sensitivity::Read,
                tags: BTreeSet::new(),
                audit_args: true,
                patterns: Vec::new(),
            });
            r.scopes.extend(e.scopes.iter().cloned());
            r.tags.extend(e.tags.iter().cloned());
            r.sensitivity = r.sensitivity.max(e.sensitivity);
            r.audit_args &= e.audit_args;
            r.patterns.push(pattern.clone());
        }
        if let Some(r) = out.as_mut() {
            if r.tags.contains("pii") {
                r.audit_args = false;
            }
        }
        out
    }

    /// Every scope referenced anywhere in the catalog.
    pub fn all_scopes(&self) -> BTreeSet<String> {
        self.entries().flat_map(|(_, _, e)| e.scopes.iter().cloned()).collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&ActionKind, &String, &CatalogEntry)> {
        self.kinds.iter().flat_map(|(k, s)| s.entries.iter().map(move |(p, e)| (k, p, e)))
    }

    /// Serialize back to YAML-compatible JSON (used by tooling that rewrites catalogs).
    pub fn to_value(&self) -> Value {
        let mut root = serde_json::Map::new();
        root.insert("version".into(), Value::from(self.version));
        for (kind, section) in &self.kinds {
            let mut m = serde_json::Map::new();
            if section.normalize != default_normalize(kind) {
                m.insert("_normalize".into(), serde_json::to_value(section.normalize).unwrap_or(Value::Null));
            }
            for (p, e) in &section.entries {
                m.insert(p.clone(), serde_json::to_value(e).unwrap_or(Value::Null));
            }
            root.insert(kind.to_string(), Value::Object(m));
        }
        Value::Object(root)
    }
}

pub fn default_normalize(kind: &ActionKind) -> NormalizeMode {
    match kind {
        ActionKind::Resource => NormalizeMode::Uri,
        _ => NormalizeMode::Name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
version: 1
tool:
  crm.update_deal: { scopes: [crm:write], sensitivity: write }
  crm.delete_deal: { scopes: [crm:write], sensitivity: write }
  "*.delete_*":    { scopes: [admin], sensitivity: write, tags: [destructive] }
resource:
  "docs://hr/**":  { scopes: [docs:hr] }
x-payment:
  payments.transfer: { scopes: [payments:write], sensitivity: write, tags: [financial] }
"#;

    #[test]
    fn overlapping_entries_merge_restrictively() {
        let c = Catalog::from_yaml_str(CAT).unwrap();
        let r = c.resolve(&ActionKind::Tool, "crm.delete_deal").unwrap();
        assert_eq!(r.scopes, BTreeSet::from(["admin".to_string(), "crm:write".to_string()]));
        assert!(r.tags.contains("destructive"));
        assert!(c.resolve(&ActionKind::Tool, "crm.unknown").is_none());
    }

    #[test]
    fn custom_kinds_and_uris() {
        let c = Catalog::from_yaml_str(CAT).unwrap();
        assert!(c.resolve(&ActionKind::Custom("x-payment".into()), "payments.transfer").is_some());
        assert!(c.resolve(&ActionKind::Resource, "docs://hr/policies/leave.md").is_some());
        assert!(c.resolve(&ActionKind::Resource, "docs://it/runbook").is_none());
    }

    #[test]
    fn rejects_bad_files() {
        assert!(Catalog::from_yaml_str("tool: {}").is_err());
        assert!(Catalog::from_yaml_str("version: 1\nbogus: {}").is_err());
        assert!(Catalog::from_yaml_str("version: 1\ntool:\n  a: { scopes: [x], typo: 1 }").is_err());
    }
}
