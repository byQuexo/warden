//! # agent-scope-rig
//!
//! Policy enforcement inside a [rig](https://github.com/0xPlaygrounds/rig) agent loop.
//!
//! [`ScopeHook`] implements `rig_agent::agent::AgentHook::on_dispatch`: every tool call the
//! model emits is checked by the agent-scope engine **before** the tool runs.
//!
//! * `allow` → the call proceeds with exactly the arguments that were checked (strictly
//!   re-parsed and patched back, so duplicate-key tricks cannot reach the tool)
//! * `require_approval` → an [`Approver`] is asked; on approval the policy is re-checked
//! * `deny` → the tool is skipped and the model sees only the generic deny message
//!
//! Use it next to the MCP gateway as a second line of defense, or on its own for in-process
//! tools. [`visible_tools`] gives the tool names the model should be offered at all.
//!
//! ```ignore
//! let hook = ScopeHook::new(engine.clone(), principal).with_prefix("crm.").with_approver(approver);
//! let agent = AgentBuilder::new(model).tools(scope_tools).hook(hook).build();
//! ```
#![forbid(unsafe_code)]

use std::sync::Arc;

use agent_scope_audit::{args_hmac, AuditSink};
use agent_scope_core::json::{parse_strict, Limits};
use agent_scope_core::{Action, ActionKind, Context, Decision, Effect, Engine, Principal};
use agent_scope_gateway::{ApprovalOutcome, ApprovalRequest, Approver};
use rig_agent::agent::{AgentHook, DispatchAction, DispatchEvent, HookContext};
use rig_core::effect::EffectKind;
use serde_json::{json, Value};

/// Supplies adapter context (time, channel …) for rules that use `context.*`.
pub type ContextFn = Arc<dyn Fn() -> Context + Send + Sync>;

/// A rig hook that authorizes every tool dispatch.
#[derive(Clone)]
pub struct ScopeHook {
    engine: Arc<Engine>,
    principal: Principal,
    prefix: String,
    approver: Option<Arc<dyn Approver>>,
    audit: Option<Arc<dyn AuditSink>>,
    context: ContextFn,
    hmac_key: Vec<u8>,
}

/// What the hook decided for one tool call (exposed for logging and tests).
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Run the tool with these (canonical) arguments.
    Run(Value),
    /// Skip the tool; the model sees this message.
    Skip(String),
}

const DENIED: &str = "This action is not permitted.";
const NOT_APPROVED: &str = "This action was not approved.";

impl ScopeHook {
    pub fn new(engine: Arc<Engine>, principal: Principal) -> Self {
        Self {
            engine,
            principal,
            prefix: String::new(),
            approver: None,
            audit: None,
            context: Arc::new(Context::default),
            hmac_key: b"agent-scope-rig".to_vec(),
        }
    }

    /// Prefix that maps rig tool names to catalog names (e.g. `crm.`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn with_approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = Some(approver);
        self
    }

    /// Record every decision; if the sink fails, the call is skipped (fail closed).
    pub fn with_audit(mut self, audit: Arc<dyn AuditSink>, hmac_key: Vec<u8>) -> Self {
        self.audit = Some(audit);
        self.hmac_key = hmac_key;
        self
    }

    pub fn with_context(mut self, f: ContextFn) -> Self {
        self.context = f;
        self
    }

    fn record(&self, action: &Action, d: &Decision) -> bool {
        let Some(sink) = &self.audit else { return true };
        let fields = json!({
            "subject": self.principal.subject.id, "agent": self.principal.agent, "act": self.principal.act,
            "effect": d.effect, "rule": d.rule, "reason": d.reason, "policy_version": d.policy_version,
            "action": {"kind": action.kind.as_str(), "name": action.name, "args_hmac": args_hmac(&self.hmac_key, &action.args)},
            "adapter": "rig",
        });
        sink.record("decision", fields).is_ok()
    }

    /// Decide one tool call. `raw_args` is the JSON text the model produced.
    pub async fn decide(&self, tool: &str, raw_args: &str) -> Verdict {
        let Ok(args) = parse_strict(raw_args, Limits::default()) else {
            return Verdict::Skip(DENIED.into());
        };
        let action = Action::tool(format!("{}{tool}", self.prefix), args.clone());
        let ctx = (self.context)();
        let d = self.engine.check(&self.principal, &action, &ctx);
        if !self.record(&action, &d) {
            return Verdict::Skip(DENIED.into());
        }
        match d.effect {
            Effect::Allow => Verdict::Run(args),
            Effect::Deny => Verdict::Skip(d.model_message),
            Effect::RequireApproval => {
                let Some(approver) = &self.approver else { return Verdict::Skip(NOT_APPROVED.into()) };
                let req = ApprovalRequest {
                    v: 1,
                    id: format!("rig-{}", d.policy_version.get(7..19).unwrap_or("")),
                    subject: self.principal.subject.id.clone(),
                    agent: self.principal.agent.clone(),
                    act: self.principal.act.clone(),
                    kind: "tool".into(),
                    name: action.name.clone(),
                    args: args.clone(),
                    args_hash: args_hmac(&self.hmac_key, &args),
                    rule: d.rule.clone(),
                    reason: d.reason.clone(),
                    policy_version: d.policy_version.clone(),
                };
                match approver.request(&req).await {
                    ApprovalOutcome::Approved { approver } if approver != self.principal.subject.id => {
                        let again = self.engine.check(&self.principal, &action, &(self.context)());
                        if again.effect == Effect::Deny || again.policy_version != d.policy_version {
                            Verdict::Skip(NOT_APPROVED.into())
                        } else {
                            Verdict::Run(args)
                        }
                    }
                    _ => Verdict::Skip(NOT_APPROVED.into()),
                }
            }
        }
    }
}

impl AgentHook for ScopeHook {
    fn name(&self) -> Option<String> {
        Some(format!("agent-scope:{}", self.engine.version()))
    }

    async fn on_dispatch(&self, _ctx: &HookContext, event: DispatchEvent<'_>) -> DispatchAction {
        // Only tool calls are authorized; completions etc. pass through.
        let (Some(name), Some(args)) = (event.tool_name(), event.tool_args()) else {
            return DispatchAction::proceed();
        };
        match self.decide(name, args).await {
            // Forward exactly what was checked.
            Verdict::Run(checked) => DispatchAction::rewrite_tool_args(event.kind, checked),
            Verdict::Skip(msg) => DispatchAction::skip(msg),
        }
    }
}

/// The subset of `tool_names` the model should be offered (`prefix` maps to catalog names).
pub fn visible_tools<'a>(
    engine: &Engine,
    principal: &Principal,
    prefix: &str,
    tool_names: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let ctx = Context::default();
    tool_names
        .into_iter()
        .filter(|n| engine.visible(principal, &Action::new(ActionKind::Tool, format!("{prefix}{n}"), Value::Null), &ctx))
        .map(str::to_string)
        .collect()
}

/// Build the effect for a tool call (useful in tests and custom runtimes).
pub fn tool_call(name: &str, args: &str) -> EffectKind {
    EffectKind::ToolCall { name: name.into(), args: args.into() }
}
