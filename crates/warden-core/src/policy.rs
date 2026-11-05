//! The policy file: roles → scopes, agents → maximum scopes and delegation rights, and
//! rules that can only **restrict** what scopes allow.
//!
//! ```yaml
//! version: 1
//! roles:
//!   sales-rep: [crm:read, crm:write]
//! agents:
//!   my-bot: { max: [crm:read, crm:write] }
//! rules:
//!   - id: big-deals-need-approval
//!     match: { kind: tool, name: crm.update_deal }
//!     approve_if: { arg: amount, min: 50000 }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::catalog::Sensitivity;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub model_messages: ModelMessages,
    #[serde(default)]
    pub roles: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub agents: BTreeMap<String, AgentDef>,
    #[serde(default)]
    pub service_subjects: ServiceSubjects,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn from_yaml_str(s: &str) -> Result<Self, String> {
        let p: Policy = serde_norway::from_str(s).map_err(|e| e.to_string())?;
        if p.version != 1 {
            return Err(format!("unsupported policy version {} (expected 1)", p.version));
        }
        Ok(p)
    }

    pub fn to_yaml_string(&self) -> String {
        serde_norway::to_string(self).unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub effect: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self { effect: "deny".into() }
    }
}

/// What the model sees when an action is denied or held for approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ModelMessages {
    /// A fixed, non-revealing sentence. Recommended: details help an attacker iterate.
    #[default]
    Generic,
    /// Includes the rule id.
    RuleId,
}

/// May tokens without a human user (client credentials) act at all?
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ServiceSubjects {
    #[default]
    Deny,
    Allow,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentDef {
    /// Upper bound of scopes this agent can ever use, whoever it acts for.
    #[serde(default)]
    pub max: Vec<String>,
    #[serde(default)]
    pub delegation: Delegation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// Agents this agent may hand work to.
    #[serde(default)]
    pub may_delegate_to: Vec<String>,
    /// Longest delegation chain under which this agent may act (0 = only directly).
    #[serde(default)]
    pub max_depth: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "match")]
    pub matcher: Match,
    /// Condition must hold, otherwise deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require: Option<Value>,
    /// Condition holds → require human approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve_if: Option<Value>,
    /// Condition holds → deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_if: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Glob over the normalized name / URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<Sensitivity>,
}

/// Which of the three rule kinds a rule is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Require,
    ApproveIf,
    DenyIf,
}

impl RuleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleKind::Require => "require",
            RuleKind::ApproveIf => "approve_if",
            RuleKind::DenyIf => "deny_if",
        }
    }
}

impl Rule {
    /// The single condition of the rule. Exactly one must be set (checked by lint).
    pub fn condition(&self) -> Option<(RuleKind, &Value)> {
        let set: Vec<(RuleKind, &Value)> = [
            (RuleKind::Require, self.require.as_ref()),
            (RuleKind::ApproveIf, self.approve_if.as_ref()),
            (RuleKind::DenyIf, self.deny_if.as_ref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();
        if set.len() == 1 {
            set.into_iter().next()
        } else {
            None
        }
    }
}
