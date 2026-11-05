//! Core data model: who acts ([`Principal`]), what they want to do ([`Action`]),
//! the environment ([`Context`]) and the answer ([`Decision`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A free-form attribute value (from token claims or an attribute resolver).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(untagged)]
pub enum AttrValue {
    Bool(bool),
    Number(f64),
    String(String),
    List(Vec<String>),
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::String(s) => Some(s),
            _ => None,
        }
    }
}

pub type Attrs = BTreeMap<String, AttrValue>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    #[default]
    User,
    Service,
}

/// The party on whose behalf an agent acts: a human user or a service account.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Subject {
    pub id: String,
    #[serde(default)]
    pub kind: SubjectKind,
    #[serde(default)]
    pub roles: BTreeSet<String>,
    #[serde(default)]
    pub attrs: Attrs,
}

impl Subject {
    pub fn user(id: impl Into<String>) -> Self {
        Self { id: id.into(), kind: SubjectKind::User, roles: BTreeSet::new(), attrs: Attrs::new() }
    }
    pub fn service(id: impl Into<String>) -> Self {
        Self { kind: SubjectKind::Service, ..Self::user(id) }
    }
    pub fn with_roles<I: IntoIterator<Item = S>, S: Into<String>>(mut self, roles: I) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_attr(mut self, key: impl Into<String>, value: AttrValue) -> Self {
        self.attrs.insert(key.into(), value);
        self
    }
}

/// A verified identity: subject + acting agent + delegation chain.
///
/// `act` lists the agents that delegated to `agent`, oldest first. For
/// `bot → research → action`, `agent = "action"` and `act = ["bot", "research"]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Principal {
    pub subject: Subject,
    pub agent: String,
    #[serde(default)]
    pub act: Vec<String>,
    /// Scopes granted by the token. `None` means "the token does not restrict scopes".
    #[serde(default)]
    pub token_scopes: Option<BTreeSet<String>>,
    /// Token expiry (unix seconds), if known.
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub issuer: Option<String>,
    /// Set when an operator acts *as* this subject ("test as user"). Such principals are
    /// read-only: every write is denied, whatever the policy says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<String>,
}

impl Principal {
    pub fn new(subject: Subject, agent: impl Into<String>) -> Self {
        Self { subject, agent: agent.into(), act: Vec::new(), token_scopes: None, expires_at: None, issuer: None, impersonated_by: None }
    }
    /// Mark the principal as impersonated by `operator` (read-only).
    pub fn impersonated_by(mut self, operator: impl Into<String>) -> Self {
        self.impersonated_by = Some(operator.into());
        self
    }
    pub fn with_agent(mut self, agent: impl Into<String>) -> Self {
        self.agent = agent.into();
        self
    }
    pub fn with_act<I: IntoIterator<Item = S>, S: Into<String>>(mut self, act: I) -> Self {
        self.act = act.into_iter().map(Into::into).collect();
        self
    }
    pub fn with_token_scopes<I: IntoIterator<Item = S>, S: Into<String>>(mut self, s: I) -> Self {
        self.token_scopes = Some(s.into_iter().map(Into::into).collect());
        self
    }
    pub fn with_expiry(mut self, exp: i64) -> Self {
        self.expires_at = Some(exp);
        self
    }
    /// Stable identity key used for session binding: subject, agent and chain.
    pub fn identity_key(&self) -> String {
        format!("{}|{}|{}", self.subject.id, self.agent, self.act.join(">"))
    }
}

/// The kind of action. Built-in kinds cover MCP and A2A; `x-…` kinds are user-defined.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ActionKind {
    Tool,
    Resource,
    Prompt,
    A2aSkill,
    Custom(String),
}

impl ActionKind {
    pub fn as_str(&self) -> &str {
        match self {
            ActionKind::Tool => "tool",
            ActionKind::Resource => "resource",
            ActionKind::Prompt => "prompt",
            ActionKind::A2aSkill => "a2a_skill",
            ActionKind::Custom(s) => s,
        }
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ActionKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tool" => ActionKind::Tool,
            "resource" => ActionKind::Resource,
            "prompt" => ActionKind::Prompt,
            "a2a_skill" => ActionKind::A2aSkill,
            other if other.starts_with("x-") && other.len() > 2 => ActionKind::Custom(other.to_string()),
            other => return Err(format!("unknown action kind `{other}` (custom kinds must start with `x-`)")),
        })
    }
}

impl TryFrom<String> for ActionKind {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<ActionKind> for String {
    fn from(k: ActionKind) -> String {
        k.as_str().to_string()
    }
}

/// Something an agent wants to do.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Action {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub kind: ActionKind,
    /// Tool/prompt/skill name or resource URI, as presented by the adapter.
    pub name: String,
    #[serde(default)]
    pub args: Value,
    /// Hash of the upstream definition (tool schema, description …) for rug-pull pinning.
    #[serde(default)]
    pub definition_hash: Option<String>,
}

impl Action {
    pub fn new(kind: ActionKind, name: impl Into<String>, args: Value) -> Self {
        Self { kind, name: name.into(), args, definition_hash: None }
    }
    pub fn tool(name: impl Into<String>, args: Value) -> Self {
        Self::new(ActionKind::Tool, name, args)
    }
    pub fn resource(uri: impl Into<String>) -> Self {
        Self::new(ActionKind::Resource, uri, Value::Null)
    }
    pub fn prompt(name: impl Into<String>, args: Value) -> Self {
        Self::new(ActionKind::Prompt, name, args)
    }
    pub fn a2a_skill(name: impl Into<String>, args: Value) -> Self {
        Self::new(ActionKind::A2aSkill, name, args)
    }
    pub fn with_definition_hash(mut self, hash: impl Into<String>) -> Self {
        self.definition_hash = Some(hash.into());
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum KillSwitch {
    #[default]
    Off,
    /// All `write` actions are denied.
    Writes,
    /// Everything is denied.
    All,
}

/// Environment supplied by the adapter, never by the model.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Context {
    #[serde(default)]
    pub kill_switch: KillSwitch,
    /// Values available to rules as `context.<key>` (e.g. `hour_utc`, `client_ip`).
    #[serde(default)]
    pub values: Attrs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Allow,
    RequireApproval,
    Deny,
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Effect::Allow => "allow",
            Effect::RequireApproval => "require_approval",
            Effect::Deny => "deny",
        })
    }
}

/// One step of the evaluation, for `explain`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// The answer. Deliberately has no `Default`: there is no "neutral" decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Decision {
    pub effect: Effect,
    /// Id of the deciding rule or built-in check (e.g. `scope.missing`).
    pub rule: String,
    /// Internal reason for audit / explain. Never show this to the model.
    pub reason: String,
    /// What the model is allowed to see.
    pub model_message: String,
    pub trace: Vec<TraceStep>,
    pub policy_version: String,
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        self.effect == Effect::Allow
    }

    /// Human-readable rendering of the evaluation trace.
    pub fn render(&self) -> String {
        let mut out = format!("effect: {}\nrule:   {}\nreason: {}\n\ntrace:\n", self.effect, self.rule, self.reason);
        for s in &self.trace {
            if s.detail.is_empty() {
                out.push_str(&format!("  {:<22} {}\n", s.step, s.outcome));
            } else {
                out.push_str(&format!("  {:<22} {:<10} {}\n", s.step, s.outcome, s.detail));
            }
        }
        out
    }
}
