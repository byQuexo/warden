//! The decision engine.
//!
//! Evaluation order (fixed):
//! 1. normalize name/URI and check argument limits
//! 2. principal: known agent, allowed delegation chain, service subjects
//! 3. kill switch (`all`)
//! 4. catalog lookup (+ lock pin) → untagged = deny
//! 5. kill switch (`writes`)
//! 6. scope gate: every required scope must be granted by role ∩ agent ∩ token ∩ each delegator
//! 7. rules (`require` / `approve_if` / `deny_if`), all matching rules evaluated
//! 8. combine: deny > require_approval > allow

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::catalog::{Catalog, NormalizeMode, Resolved, Sensitivity};
use crate::constraint::{self, Cond, Env, Tri};
use crate::error::BuildError;
use crate::json::{self, Limits};
use crate::lint::{self, Finding, Level};
use crate::lock::Lock;
use crate::model::{Action, ActionKind, AttrValue, Context, Decision, Effect, KillSwitch, Principal, SubjectKind, TraceStep};
use crate::normalize::{normalize_name, normalize_uri};
use crate::policy::{ModelMessages, Policy, RuleKind, ServiceSubjects};

/// A user-supplied, pure, synchronous argument check (`custom: <name>` in a policy).
///
/// Policies using custom constraints are **not portable** to the TypeScript/WASM engine
/// unless the same constraint is registered there; unregistered names evaluate to deny.
pub trait CustomConstraint: Send + Sync {
    fn eval(&self, value: &Value, principal: &Principal, ctx: &Context) -> Tri;
}

impl<F> CustomConstraint for F
where
    F: Fn(&Value, &Principal, &Context) -> Tri + Send + Sync,
{
    fn eval(&self, value: &Value, principal: &Principal, ctx: &Context) -> Tri {
        self(value, principal, ctx)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledMatch {
    pub kind: Option<ActionKind>,
    pub name: Option<String>,
    pub tag: Option<String>,
    pub sensitivity: Option<Sensitivity>,
}

#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub id: String,
    pub kind: RuleKind,
    pub(crate) matcher: CompiledMatch,
    pub cond: Cond,
}

impl CompiledRule {
    /// Does this rule apply to the (normalized) action?
    pub fn applies_to(&self, catalog: &Catalog, kind: &ActionKind, name: &str) -> bool {
        match catalog.resolve(kind, name) {
            Some(r) => self.applies(kind, name, catalog.normalize_mode(kind), &r),
            None => false,
        }
    }

    fn applies(&self, kind: &ActionKind, name: &str, mode: NormalizeMode, r: &Resolved) -> bool {
        let m = &self.matcher;
        if m.kind.as_ref().is_some_and(|k| k != kind) {
            return false;
        }
        if let Some(pattern) = &m.name {
            if !crate::glob::matches(pattern, name, crate::glob::separator_for_uri(mode == NormalizeMode::Uri)) {
                return false;
            }
        }
        if m.tag.as_ref().is_some_and(|t| !r.tags.contains(t)) {
            return false;
        }
        if m.sensitivity.is_some_and(|s| s != r.sensitivity) {
            return false;
        }
        true
    }
}

/// An immutable, fully validated engine. Cheap to share behind an `Arc`.
pub struct Engine {
    catalog: Catalog,
    policy: Policy,
    rules: Vec<CompiledRule>,
    lock: Option<Lock>,
    version: String,
    customs: BTreeMap<String, Arc<dyn CustomConstraint>>,
    warnings: Vec<Finding>,
    limits: Limits,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").field("version", &self.version).field("rules", &self.rules.len()).finish()
    }
}

#[derive(Default)]
pub struct EngineBuilder {
    policy: Option<Result<Policy, String>>,
    catalog: Option<Result<Catalog, String>>,
    lock: Option<Result<Lock, String>>,
    customs: BTreeMap<String, Arc<dyn CustomConstraint>>,
    limits: Option<Limits>,
}

impl EngineBuilder {
    pub fn policy_yaml(mut self, s: &str) -> Self {
        self.policy = Some(Policy::from_yaml_str(s));
        self
    }
    pub fn policy(mut self, p: Policy) -> Self {
        self.policy = Some(Ok(p));
        self
    }
    pub fn catalog_yaml(mut self, s: &str) -> Self {
        self.catalog = Some(Catalog::from_yaml_str(s));
        self
    }
    pub fn catalog(mut self, c: Catalog) -> Self {
        self.catalog = Some(Ok(c));
        self
    }
    pub fn lock_json(mut self, s: &str) -> Self {
        self.lock = Some(Lock::from_json_str(s));
        self
    }
    pub fn lock(mut self, l: Option<Lock>) -> Self {
        self.lock = l.map(Ok);
        self
    }
    pub fn custom(mut self, name: &str, c: Arc<dyn CustomConstraint>) -> Self {
        self.customs.insert(name.to_string(), c);
        self
    }
    pub fn limits(mut self, l: Limits) -> Self {
        self.limits = Some(l);
        self
    }

    pub fn build(self) -> Result<Engine, BuildError> {
        let policy = self
            .policy
            .ok_or_else(|| BuildError::Parse { file: "policy", message: "no policy given".into() })?
            .map_err(|m| BuildError::Parse { file: "policy", message: m })?;
        let catalog = self
            .catalog
            .ok_or_else(|| BuildError::Parse { file: "catalog", message: "no catalog given".into() })?
            .map_err(|m| BuildError::Parse { file: "catalog", message: m })?;
        let lock = self.lock.transpose().map_err(|m| BuildError::Parse { file: "lock", message: m })?;

        let (rules, mut findings) = compile_rules(&policy);
        findings.extend(lint::lint(&policy, &catalog, &rules, &self.customs));
        let errors: Vec<Finding> = findings.iter().filter(|f| f.level == Level::Error).cloned().collect();
        if !errors.is_empty() {
            return Err(BuildError::Lint(errors));
        }
        let version = version_hash(&policy, &catalog, lock.as_ref());
        Ok(Engine {
            catalog,
            policy,
            rules,
            lock,
            version,
            customs: self.customs,
            warnings: findings,
            limits: self.limits.unwrap_or_default(),
        })
    }
}

/// Compile all rules; rules that fail to compile are reported as lint errors.
pub fn compile_rules(policy: &Policy) -> (Vec<CompiledRule>, Vec<Finding>) {
    let mut rules = Vec::new();
    let mut findings = Vec::new();
    for r in &policy.rules {
        if r.approve_by == crate::policy::ApproveBy::Subject && r.approve_if.is_none() {
            findings.push(Finding::error("rule.approve_by", format!("rule `{}`: approve_by only applies to approve_if rules", r.id)));
            continue;
        }
        let Some((kind, v)) = r.condition() else {
            findings
                .push(Finding::error("rule.condition", format!("rule `{}` must have exactly one of require / approve_if / deny_if", r.id)));
            continue;
        };
        let cond = match constraint::compile(v) {
            Ok(c) => c,
            Err(e) => {
                findings.push(Finding::error("rule.invalid", format!("rule `{}`: {e}", r.id)));
                continue;
            }
        };
        let kind_parsed = match r.matcher.kind.as_deref().map(str::parse::<ActionKind>).transpose() {
            Ok(k) => k,
            Err(e) => {
                findings.push(Finding::error("rule.invalid", format!("rule `{}`: {e}", r.id)));
                continue;
            }
        };
        rules.push(CompiledRule {
            id: r.id.clone(),
            kind,
            matcher: CompiledMatch {
                kind: kind_parsed,
                name: r.matcher.name.clone(),
                tag: r.matcher.tag.clone(),
                sensitivity: r.matcher.sensitivity,
            },
            cond,
        });
    }
    (rules, findings)
}

fn version_hash(policy: &Policy, catalog: &Catalog, lock: Option<&Lock>) -> String {
    let v = serde_json::json!({
        "policy": serde_json::to_value(policy).unwrap_or(Value::Null),
        "catalog": catalog.to_value(),
        "lock": lock.map(|l| serde_json::to_value(l).unwrap_or(Value::Null)),
    });
    format!("sha256:{}", hex::encode(Sha256::digest(json::canonical(&v).as_bytes())))
}

/// `docs:*` grants `docs:hr`; everything else is exact.
pub fn scope_matches(pattern: &str, scope: &str) -> bool {
    if pattern == scope {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) if prefix.ends_with(':') => scope.starts_with(prefix) && scope.len() > prefix.len(),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Decide,
    Visibility,
}

struct Trace {
    steps: Vec<TraceStep>,
}

impl Trace {
    fn push(&mut self, step: &str, outcome: &str, detail: impl Into<String>) {
        self.steps.push(TraceStep { step: step.into(), outcome: outcome.into(), detail: detail.into() });
    }
}

impl Engine {
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// Content hash of policy + catalog + lock. Goes into every decision and audit event.
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }
    pub fn lock(&self) -> Option<&Lock> {
        self.lock.as_ref()
    }
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }
    /// Is a hold by this rule decided by the requesting subject itself (`approve_by: subject`)?
    pub fn approved_by_subject(&self, rule: &str) -> bool {
        self.policy.rules.iter().any(|r| r.id == rule && r.approve_by == crate::policy::ApproveBy::Subject)
    }
    /// Non-fatal lint findings collected at build time.
    pub fn warnings(&self) -> &[Finding] {
        &self.warnings
    }

    /// Decide. Never panics, never returns an error: every failure is a `deny`.
    pub fn check(&self, principal: &Principal, action: &Action, ctx: &Context) -> Decision {
        match catch_unwind(AssertUnwindSafe(|| self.evaluate(principal, action, ctx, Mode::Decide))) {
            Ok(d) => d,
            Err(_) => self.decision(
                Effect::Deny,
                "internal.error",
                "engine panicked; failing closed".into(),
                vec![TraceStep { step: "internal".into(), outcome: "panic".into(), detail: String::new() }],
            ),
        }
    }

    /// Alias for [`Engine::check`]; the trace is always complete.
    pub fn explain(&self, principal: &Principal, action: &Action, ctx: &Context) -> Decision {
        self.check(principal, action, ctx)
    }

    /// Should this action be listed to the model? Argument-dependent rules do not hide an
    /// action; only scope, catalog, pinning, kill switch and unconditional `deny_if` do.
    pub fn visible(&self, principal: &Principal, action: &Action, ctx: &Context) -> bool {
        catch_unwind(AssertUnwindSafe(|| self.evaluate(principal, action, ctx, Mode::Visibility)))
            .map(|d| d.effect != Effect::Deny)
            .unwrap_or(false)
    }

    /// Filter names of one kind down to the visible ones.
    pub fn filter<'a>(
        &self,
        principal: &Principal,
        kind: &ActionKind,
        names: impl IntoIterator<Item = &'a str>,
        ctx: &Context,
    ) -> Vec<String> {
        names
            .into_iter()
            .filter(|n| self.visible(principal, &Action::new(kind.clone(), *n, Value::Null), ctx))
            .map(str::to_string)
            .collect()
    }

    /// All catalog scopes the principal effectively holds.
    pub fn effective_scopes(&self, principal: &Principal) -> BTreeSet<String> {
        if self.check_principal(principal).is_err() {
            return BTreeSet::new();
        }
        self.catalog.all_scopes().into_iter().filter(|s| self.scope_granted(principal, s).is_ok()).collect()
    }

    fn decision(&self, effect: Effect, rule: &str, reason: String, trace: Vec<TraceStep>) -> Decision {
        let model_message = match (effect, self.policy.model_messages) {
            (Effect::Allow, _) => String::new(),
            (Effect::Deny, ModelMessages::Generic) => "This action is not permitted.".to_string(),
            (Effect::Deny, ModelMessages::RuleId) => format!("This action is not permitted (rule: {rule})."),
            (Effect::RequireApproval, ModelMessages::Generic) => "This action requires human approval.".to_string(),
            (Effect::RequireApproval, ModelMessages::RuleId) => {
                format!("This action requires human approval (rule: {rule}).")
            }
        };
        Decision { effect, rule: rule.to_string(), reason, model_message, trace, policy_version: self.version.clone() }
    }

    fn check_principal(&self, p: &Principal) -> Result<(), (&'static str, String)> {
        let Some(agent) = self.policy.agents.get(&p.agent) else {
            return Err(("principal.unknown_agent", format!("agent `{}` is not defined in the policy", p.agent)));
        };
        if p.subject.kind == SubjectKind::Service && self.policy.service_subjects == ServiceSubjects::Deny {
            return Err(("principal.service_subject", "service subjects are not allowed by this policy".into()));
        }
        for actor in &p.act {
            if !self.policy.agents.contains_key(actor) {
                return Err(("principal.delegation", format!("unknown agent `{actor}` in delegation chain")));
            }
        }
        let mut chain: Vec<&str> = p.act.iter().map(String::as_str).collect();
        chain.push(&p.agent);
        for w in chain.windows(2) {
            let allowed = self.policy.agents.get(w[0]).is_some_and(|a| a.delegation.may_delegate_to.iter().any(|t| t == w[1]));
            if !allowed {
                return Err(("principal.delegation", format!("`{}` may not delegate to `{}`", w[0], w[1])));
            }
        }
        if p.act.len() > agent.delegation.max_depth {
            return Err((
                "principal.delegation_depth",
                format!("chain depth {} exceeds max_depth {} of `{}`", p.act.len(), agent.delegation.max_depth, p.agent),
            ));
        }
        Ok(())
    }

    fn scope_granted(&self, p: &Principal, scope: &str) -> Result<(), String> {
        let by_role =
            p.subject.roles.iter().filter_map(|r| self.policy.roles.get(r)).any(|scopes| scopes.iter().any(|s| scope_matches(s, scope)));
        if !by_role {
            return Err(format!("no role of `{}` grants `{scope}`", p.subject.id));
        }
        let agent_max = |a: &str| self.policy.agents.get(a).is_some_and(|d| d.max.iter().any(|s| scope_matches(s, scope)));
        if !agent_max(&p.agent) {
            return Err(format!("agent `{}` max does not include `{scope}`", p.agent));
        }
        if let Some(ts) = &p.token_scopes {
            if !ts.iter().any(|s| scope_matches(s, scope)) {
                return Err(format!("token does not carry `{scope}`"));
            }
        }
        for actor in &p.act {
            if !agent_max(actor) {
                return Err(format!("delegating agent `{actor}` does not hold `{scope}`"));
            }
        }
        Ok(())
    }

    fn evaluate(&self, p: &Principal, a: &Action, ctx: &Context, mode: Mode) -> Decision {
        let mut t = Trace { steps: Vec::new() };
        macro_rules! deny {
            ($rule:expr, $reason:expr) => {{
                let reason: String = $reason;
                t.push("result", "deny", format!("{}: {}", $rule, reason));
                return self.decision(Effect::Deny, $rule, reason, t.steps);
            }};
        }

        // 1. normalize
        let norm_mode = self.catalog.normalize_mode(&a.kind);
        let name = match norm_mode {
            NormalizeMode::Name => normalize_name(&a.name).map_err(|e| ("normalize.name", e.to_string())),
            NormalizeMode::Uri => normalize_uri(&a.name).map_err(|e| ("normalize.uri", e.to_string())),
        };
        let name = match name {
            Ok(n) => n,
            Err((rule, why)) => deny!(rule, why),
        };
        if let Err(e) = json::check_limits(&a.args, self.limits) {
            deny!("normalize.args", e.to_string());
        }
        t.push("normalize", "ok", format!("{} {}", a.kind, name));

        // 2. principal
        if let Err((rule, why)) = self.check_principal(p) {
            deny!(rule, why);
        }
        t.push(
            "principal",
            "ok",
            format!(
                "subject={} agent={}{}",
                p.subject.id,
                p.agent,
                if p.act.is_empty() { String::new() } else { format!(" act={}", p.act.join(">")) }
            ),
        );

        // Impersonation is visible to rules as `context.impersonation` / `context.impersonated_by`.
        let imp_ctx;
        let ctx = match &p.impersonated_by {
            Some(by) => {
                t.push("impersonation", "ok", format!("by={by} (read-only)"));
                let mut c = ctx.clone();
                c.values.insert("impersonation".into(), AttrValue::Bool(true));
                c.values.insert("impersonated_by".into(), AttrValue::String(by.clone()));
                imp_ctx = c;
                &imp_ctx
            }
            None => ctx,
        };

        // 3. kill switch (all)
        if ctx.kill_switch == KillSwitch::All {
            deny!("kill_switch", "kill switch is set to `all`".into());
        }

        // 4. catalog + pin
        let resolved = match self.catalog.resolve(&a.kind, &name) {
            Some(r) if !r.scopes.is_empty() => r,
            _ => deny!("catalog.untagged", format!("`{name}` has no catalog entry with scopes")),
        };
        t.push(
            "catalog",
            "ok",
            format!("needs [{}] sensitivity={:?} tags=[{}]", join(&resolved.scopes), resolved.sensitivity, join(&resolved.tags)),
        );
        if let Some(lock) = &self.lock {
            match lock.pinned(a.kind.as_str(), &name) {
                None => {}
                Some(None) => deny!("catalog.unpinned", format!("`{name}` is not pinned in catalog.lock")),
                Some(Some(h)) if a.definition_hash.as_deref() == Some(h) => t.push("pin", "ok", ""),
                Some(Some(_)) => deny!("catalog.unpinned", format!("definition of `{name}` changed since it was pinned")),
            }
        }

        if p.impersonated_by.is_some() && resolved.sensitivity == Sensitivity::Write {
            deny!("impersonation.read_only", "impersonated sessions cannot write".into());
        }

        // 5. kill switch (writes)
        if ctx.kill_switch == KillSwitch::Writes && resolved.sensitivity == Sensitivity::Write {
            deny!("kill_switch", "kill switch is set to `writes`".into());
        }

        // 6. scope gate
        for s in &resolved.scopes {
            if let Err(why) = self.scope_granted(p, s) {
                deny!("scope.missing", why);
            }
        }
        t.push("scope_gate", "ok", join(&resolved.scopes));

        // 7. rules
        let customs = &self.customs;
        let env = Env { principal: p, action: a, ctx, customs };
        let mut first_deny: Option<(String, String)> = None;
        let mut first_approval: Option<(String, String)> = None;
        for r in self.rules.iter().filter(|r| r.applies(&a.kind, &name, norm_mode, &resolved)) {
            if mode == Mode::Visibility && !(r.kind == RuleKind::DenyIf && matches!(r.cond, Cond::Always)) {
                continue;
            }
            let res = r.cond.eval(&env);
            let (outcome, effect, detail) = match (r.kind, &res) {
                (_, Tri::Unknown(why)) => ("deny", Some(Effect::Deny), why.clone()),
                (RuleKind::Require, Tri::True) => ("pass", None, "condition holds".into()),
                (RuleKind::Require, Tri::False) => ("deny", Some(Effect::Deny), "required condition does not hold".into()),
                (RuleKind::ApproveIf, Tri::True) => ("approval", Some(Effect::RequireApproval), "condition holds".into()),
                (RuleKind::ApproveIf, Tri::False) => ("pass", None, "condition does not hold".into()),
                (RuleKind::DenyIf, Tri::True) => ("deny", Some(Effect::Deny), "deny condition holds".into()),
                (RuleKind::DenyIf, Tri::False) => ("pass", None, "deny condition does not hold".into()),
            };
            t.push(&format!("rule:{}", r.id), outcome, format!("{} — {}", r.kind.as_str(), detail));
            match effect {
                Some(Effect::Deny) if first_deny.is_none() => first_deny = Some((r.id.clone(), detail)),
                Some(Effect::RequireApproval) if first_approval.is_none() => first_approval = Some((r.id.clone(), detail)),
                _ => {}
            }
        }

        // 8. combine
        if let Some((rule, why)) = first_deny {
            deny!(&rule, why);
        }
        if let Some((rule, why)) = first_approval {
            t.push("result", "require_approval", rule.clone());
            return self.decision(Effect::RequireApproval, &rule, why, t.steps);
        }
        t.push("result", "allow", "");
        self.decision(Effect::Allow, "scope.granted", "all required scopes granted; no rule objected".into(), t.steps)
    }
}

fn join(s: &BTreeSet<String>) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(", ")
}
