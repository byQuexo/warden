//! Static checks over policy + catalog. Errors stop the engine from being built;
//! warnings are reported by `agent-scope lint`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::catalog::{Catalog, NormalizeMode};
use crate::engine::{scope_matches, CompiledRule, CustomConstraint};
use crate::glob;
use crate::normalize::{collision_key, normalize_name};
use crate::policy::{Policy, RuleKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub level: Level,
    pub code: String,
    pub message: String,
}

impl Finding {
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self { level: Level::Error, code: code.into(), message: message.into() }
    }
    pub fn warning(code: &str, message: impl Into<String>) -> Self {
        Self { level: Level::Warning, code: code.into(), message: message.into() }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lvl = match self.level {
            Level::Error => "error",
            Level::Warning => "warning",
        };
        write!(f, "[{lvl}] {}: {}", self.code, self.message)
    }
}

fn valid_scope(s: &str) -> bool {
    let body = s.strip_suffix(":*").unwrap_or(s);
    !body.is_empty()
        && body.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '_' | '-' | '.'))
        && !body.starts_with(':')
        && !body.ends_with(':')
}

pub fn lint(
    policy: &Policy,
    catalog: &Catalog,
    rules: &[CompiledRule],
    customs: &BTreeMap<String, Arc<dyn CustomConstraint>>,
) -> Vec<Finding> {
    let mut f = Vec::new();

    if policy.defaults.effect != "deny" {
        f.push(Finding::error("defaults.effect", "`defaults.effect` must be `deny`; allow-by-default is not supported"));
    }

    // Scopes
    let catalog_scopes = catalog.all_scopes();
    let mut granted: BTreeSet<&str> = BTreeSet::new();
    for (role, scopes) in &policy.roles {
        for s in scopes {
            if !valid_scope(s) {
                f.push(Finding::error("scope.invalid", format!("role `{role}`: scope `{s}` is malformed (bare `*` is not allowed)")));
            }
            granted.insert(s);
            if !catalog_scopes.iter().any(|c| scope_matches(s, c)) {
                f.push(Finding::warning("scope.unused", format!("role `{role}` grants `{s}`, which no catalog entry requires")));
            }
        }
    }
    for (agent, def) in &policy.agents {
        for s in &def.max {
            if !valid_scope(s) {
                f.push(Finding::error("scope.invalid", format!("agent `{agent}`: scope `{s}` is malformed")));
            }
            if !catalog_scopes.iter().any(|c| scope_matches(s, c)) {
                f.push(Finding::warning("scope.unused", format!("agent `{agent}` max includes `{s}`, which no catalog entry requires")));
            }
        }
        for target in &def.delegation.may_delegate_to {
            if !policy.agents.contains_key(target) {
                f.push(Finding::error("agent.unknown", format!("agent `{agent}` may delegate to unknown agent `{target}`")));
            }
        }
    }
    for c in &catalog_scopes {
        if !valid_scope(c) {
            f.push(Finding::error("scope.invalid", format!("catalog scope `{c}` is malformed")));
        }
        if !granted.iter().any(|g| scope_matches(g, c)) {
            f.push(Finding::warning("scope.ungranted", format!("no role grants `{c}`; actions requiring it are dead")));
        }
    }

    // Catalog patterns and collisions
    for (kind, section) in &catalog.kinds {
        let mut seen: BTreeMap<String, &String> = BTreeMap::new();
        let sep = glob::separator_for_uri(section.normalize == NormalizeMode::Uri);
        for (pattern, entry) in &section.entries {
            if entry.scopes.is_empty() {
                f.push(Finding::warning("catalog.untagged", format!("{kind} `{pattern}` has no scopes and is always denied")));
            }
            if section.normalize == NormalizeMode::Name {
                let probe = pattern.replace('*', "x");
                if normalize_name(&probe).as_deref() != Ok(probe.as_str()) {
                    f.push(Finding::error("catalog.name", format!("{kind} pattern `{pattern}` is not a normalized name ([a-z0-9_.-])")));
                }
                if !glob::is_glob(pattern) {
                    if let Some(prev) = seen.insert(collision_key(pattern), pattern) {
                        f.push(Finding::error("catalog.collision", format!("{kind} `{prev}` and `{pattern}` collide after normalization")));
                    }
                }
            }
            for other in section.entries.keys() {
                if other != pattern && glob::is_glob(other) && glob::matches(other, pattern, sep) {
                    f.push(Finding::warning(
                        "catalog.overlap",
                        format!("{kind} `{pattern}` also matches `{other}`; scopes and tags of both apply"),
                    ));
                }
            }
        }
    }

    // Rules
    let mut ids = BTreeSet::new();
    for r in &policy.rules {
        if !ids.insert(&r.id) {
            f.push(Finding::error("rule.duplicate", format!("duplicate rule id `{}`", r.id)));
        }
        if r.matcher.kind.is_none() && r.matcher.name.is_none() && r.matcher.tag.is_none() && r.matcher.sensitivity.is_none() {
            f.push(Finding::error("rule.match", format!("rule `{}` has an empty match", r.id)));
        }
    }
    for r in rules {
        if !rule_reaches_catalog(r, catalog) {
            f.push(Finding::error("rule.unreachable", format!("rule `{}` matches no catalog entry", r.id)));
        }
        if r.kind == RuleKind::DenyIf && r.cond.uses_string_match() {
            f.push(Finding::warning(
                "rule.denylist",
                format!("rule `{}` uses deny_if with string matching; denylists are bypassable, prefer `require`", r.id),
            ));
        }
        if r.kind == RuleKind::Require && matches!(r.cond, crate::constraint::Cond::Always) {
            f.push(Finding::warning("rule.noop", format!("rule `{}` is `require: always` and has no effect", r.id)));
        }
        for name in r.cond.custom_names() {
            if customs.contains_key(&name) {
                f.push(Finding::warning(
                    "rule.custom",
                    format!("rule `{}` uses custom constraint `{name}`; the policy is not portable to other runtimes", r.id),
                ));
            } else {
                f.push(Finding::error("rule.custom", format!("rule `{}` uses unregistered custom constraint `{name}`", r.id)));
            }
        }
    }
    f
}

fn rule_reaches_catalog(r: &CompiledRule, catalog: &Catalog) -> bool {
    let m = &r.matcher;
    catalog.kinds.iter().any(|(kind, section)| {
        if m.kind.as_ref().is_some_and(|k| k != kind) {
            return false;
        }
        let sep = glob::separator_for_uri(section.normalize == NormalizeMode::Uri);
        section.entries.iter().any(|(pattern, e)| {
            let name_ok = m.name.as_ref().is_none_or(|n| n == pattern || glob::matches(n, pattern, sep) || glob::matches(pattern, n, sep));
            let tag_ok = m.tag.as_ref().is_none_or(|t| e.tags.contains(t));
            let sens_ok = m.sensitivity.is_none_or(|s| s == e.sensitivity);
            name_ok && tag_ok && sens_ok
        })
    })
}
