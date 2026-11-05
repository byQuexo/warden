//! Scenario files and the runner.
//!
//! ```yaml
//! suite: acme-reference
//! principals:
//!   henrik: { subject: { id: henrik, roles: [hr-lead], attrs: { org_unit: hr } }, agent: acme-bot }
//! cases:
//!   - id: A1
//!     title: HR lead asks for another unit's salaries
//!     as: henrik
//!     action: { kind: tool, name: hr.get_salary, args: { unit: sales } }
//!     expect: { effect: deny, rule: salary-only-own-unit }
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use warden_core::json::{parse_strict, Limits};
use warden_core::{Action, Context, Effect, Engine, Principal};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub suite: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub principals: BTreeMap<String, Principal>,
    pub cases: Vec<Case>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    #[serde(default)]
    pub title: String,
    /// Name of a principal in `principals`.
    #[serde(default, rename = "as", skip_serializing_if = "Option::is_none")]
    pub as_: Option<String>,
    /// Inline principal (instead of `as`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<Principal>,
    pub action: Action,
    /// Raw JSON arguments, parsed strictly (duplicate keys etc.). Overrides `action.args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Context>,
    pub expect: Expect,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Expect {
    pub effect: Option<Effect>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Actual {
    pub effect: Effect,
    pub rule: String,
    pub visible: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseResult {
    pub suite: String,
    pub id: String,
    pub title: String,
    pub passed: bool,
    pub expect: Expect,
    pub actual: Actual,
    /// Gate category of a failure: `scope_violation`, `unapproved_write`, `delegation_escalation`, `mismatch`.
    pub failure: Option<String>,
    /// Rules evaluated and their outcome (`deny`, `approval`, `pass`), for coverage.
    pub rules: Vec<(String, String)>,
}

impl Suite {
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        let suite: Suite = serde_norway::from_str(s).map_err(|e| e.to_string())?;
        for c in &suite.cases {
            match (&c.as_, &c.principal) {
                (Some(n), None) if !suite.principals.contains_key(n) => {
                    return Err(format!("case {}: unknown principal `{n}`", c.id));
                }
                (Some(_), Some(_)) | (None, None) => {
                    return Err(format!("case {}: needs exactly one of `as` or `principal`", c.id));
                }
                _ => {}
            }
        }
        Ok(suite)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_yaml_str(&t).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn principal(&self, c: &Case) -> Option<Principal> {
        c.principal.clone().or_else(|| c.as_.as_ref().and_then(|n| self.principals.get(n).cloned()))
    }
}

/// Evaluate one case with a known principal.
pub fn run_case(engine: &Engine, suite: &str, principal: &Principal, c: &Case) -> CaseResult {
    let ctx = c.context.clone().unwrap_or_default();
    let mut action = c.action.clone();
    let (effect, rule, visible, rules) = match c.args_raw.as_deref().map(|raw| parse_strict(raw, Limits::default())) {
        Some(Err(_)) => (Effect::Deny, "normalize.args".to_string(), false, vec![]),
        parsed => {
            if let Some(Ok(v)) = parsed {
                action.args = v;
            }
            let d = engine.check(principal, &action, &ctx);
            let visible = engine.visible(principal, &action, &ctx);
            let rules = d.trace.iter().filter_map(|s| s.step.strip_prefix("rule:").map(|r| (r.to_string(), s.outcome.clone()))).collect();
            (d.effect, d.rule, visible, rules)
        }
    };
    let e = &c.expect;
    let passed =
        e.effect.is_none_or(|x| x == effect) && e.rule.as_ref().is_none_or(|r| r == &rule) && e.visible.is_none_or(|v| v == visible);
    let failure = (!passed).then(|| {
        let delegated = !principal.act.is_empty();
        match (e.effect, effect) {
            (Some(Effect::Deny), Effect::Allow | Effect::RequireApproval) if delegated => "delegation_escalation",
            (Some(Effect::Deny), Effect::Allow | Effect::RequireApproval) => "scope_violation",
            (Some(Effect::RequireApproval), Effect::Allow) => "unapproved_write",
            _ if e.visible == Some(false) && visible => "scope_violation",
            _ => "mismatch",
        }
        .to_string()
    });
    CaseResult {
        suite: suite.to_string(),
        id: c.id.clone(),
        title: c.title.clone(),
        passed,
        expect: e.clone(),
        actual: Actual { effect, rule, visible },
        failure,
        rules,
    }
}

/// Run every case of a suite.
pub fn run_cases(engine: &Engine, suite: &Suite) -> Vec<CaseResult> {
    suite
        .cases
        .iter()
        .map(|c| match suite.principal(c) {
            Some(p) => run_case(engine, &suite.suite, &p, c),
            None => CaseResult {
                suite: suite.suite.clone(),
                id: c.id.clone(),
                title: c.title.clone(),
                passed: false,
                expect: c.expect.clone(),
                actual: super::scenario::Actual { effect: Effect::Deny, rule: "eval.no_principal".into(), visible: false },
                failure: Some("mismatch".into()),
                rules: vec![],
            },
        })
        .collect()
}
