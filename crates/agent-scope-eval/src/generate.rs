//! Attack cases generated from a catalog + policy.
//!
//! Every generated case expects `deny`. The expectations follow from the evaluation rules
//! (spec), not from running the engine, so a broken engine fails them. Generated principals
//! use synthetic roles/agents (`__eval_*`) added to a copy of the policy, which lets the
//! generator probe one boundary at a time without knowing anything about your users.

use std::collections::{BTreeMap, BTreeSet};

use agent_scope_core::catalog::{CatalogEntry, Sensitivity};
use agent_scope_core::constraint::{Op, Operand, Placeholder};
use agent_scope_core::engine::scope_matches;
use agent_scope_core::glob::is_glob;
use agent_scope_core::policy::{AgentDef, ServiceSubjects};
use agent_scope_core::{Action, ActionKind, AttrValue, Catalog, Context, Effect, Engine, KillSwitch, Lock, Policy, Principal, Subject};
use serde_json::{json, Value};

use crate::scenario::{Case, Expect, Suite};

pub struct Generated {
    /// Engine over the augmented policy; run the generated suite against this one.
    pub engine: Engine,
    pub suite: Suite,
}

const ALL: &str = "__eval_all";
const AGENT: &str = "__eval_agent";
const VALUE: &str = "eval-value";

fn deny(rule: Option<&str>, visible: Option<bool>) -> Expect {
    Expect { effect: Some(Effect::Deny), rule: rule.map(str::to_string), visible }
}

fn homoglyph(name: &str) -> Option<String> {
    let (i, c) = name.char_indices().find(|(_, c)| matches!(c, 'a' | 'e' | 'o' | 'c' | 'p'))?;
    let look_alike = match c {
        'a' => '\u{0430}',
        'e' => '\u{0435}',
        'o' => '\u{043e}',
        'c' => '\u{0441}',
        _ => '\u{0440}',
    };
    let mut s = name.to_string();
    s.replace_range(i..i + c.len_utf8(), &look_alike.to_string());
    Some(s)
}

pub fn generate(policy: &Policy, catalog: &Catalog, lock: Option<&Lock>) -> Result<Generated, String> {
    let base = Engine::builder().policy(policy.clone()).catalog(catalog.clone()).lock(lock.cloned()).build().map_err(|e| e.to_string())?;
    let scopes: Vec<String> = catalog.all_scopes().into_iter().collect();

    // Augmented policy: an all-scopes role, one "all but X" role per scope, an all-scopes agent.
    let mut aug = policy.clone();
    aug.roles.insert(ALL.into(), scopes.clone());
    let mut minus_role: BTreeMap<String, String> = BTreeMap::new();
    for (i, s) in scopes.iter().enumerate() {
        let role = format!("__eval_minus_{i}");
        aug.roles.insert(role.clone(), scopes.iter().filter(|x| *x != s).cloned().collect());
        minus_role.insert(s.clone(), role);
    }
    aug.agents.insert(AGENT.into(), AgentDef { max: scopes.clone(), ..Default::default() });

    // Attributes referenced by rules, so argument checks are reached with a full principal.
    let mut attrs: BTreeMap<String, AttrValue> = BTreeMap::new();
    for r in base.rules() {
        for (_, op) in r.cond.arg_checks() {
            match op {
                Op::In(Operand::Placeholder(Placeholder::SubjectAttr(k))) => {
                    attrs.insert(k.clone(), AttrValue::List(vec![VALUE.into()]));
                }
                Op::Equals(Operand::Placeholder(Placeholder::SubjectAttr(k))) => {
                    attrs.entry(k.clone()).or_insert(AttrValue::String(VALUE.into()));
                }
                _ => {}
            }
        }
    }
    let mut god_subject = Subject::user("__eval__").with_roles([ALL]);
    for (k, v) in &attrs {
        god_subject = god_subject.with_attr(k.clone(), v.clone());
    }
    let god = Principal::new(god_subject, AGENT);

    let exact: Vec<(ActionKind, String, CatalogEntry)> = catalog
        .entries()
        .filter(|(_, p, e)| !is_glob(p) && !e.scopes.is_empty())
        .map(|(k, p, e)| (k.clone(), p.clone(), e.clone()))
        .collect();
    let act = |kind: &ActionKind, name: &str, args: Value| {
        let mut a = Action::new(kind.clone(), name, args);
        if let Some(Some(h)) = lock.and_then(|l| l.pinned(kind.as_str(), name)) {
            a = a.with_definition_hash(h);
        }
        a
    };

    let mut cases = Vec::new();
    let mut push =
        |id: String, title: String, p: Principal, action: Action, expect: Expect, ctx: Option<Context>, raw: Option<String>, cat: &str| {
            cases.push(Case {
                id,
                title,
                as_: None,
                principal: Some(p),
                action,
                args_raw: raw,
                context: ctx,
                expect,
                category: Some(cat.into()),
            });
        };

    // 1. Every required scope is necessary.
    for (kind, name, e) in &exact {
        let resolved = catalog.resolve(kind, name).map(|r| r.scopes).unwrap_or_default();
        for s in &resolved {
            let Some(role) = minus_role.get(s) else { continue };
            let p = Principal::new(Subject::user("__eval__").with_roles([role.as_str()]), AGENT);
            push(
                format!("G-SCOPE {kind}:{name} without {s}"),
                format!("{name} needs {s}"),
                p,
                act(kind, name, json!({})),
                deny(Some("scope.missing"), Some(false)),
                None,
                None,
                "scope",
            );
        }
        let _ = e;
    }

    // 2. Agent ceilings: an agent never exceeds its `max`, whoever it acts for.
    for (agent, def) in &policy.agents {
        for (kind, name, _) in &exact {
            let needed = catalog.resolve(kind, name).map(|r| r.scopes).unwrap_or_default();
            if needed.iter().all(|s| def.max.iter().any(|m| scope_matches(m, s))) {
                continue;
            }
            let p = Principal::new(god.subject.clone(), agent.as_str());
            push(
                format!("G-AGENT {agent} {kind}:{name}"),
                format!("{agent} may not use {name}"),
                p,
                act(kind, name, json!({})),
                deny(Some("scope.missing"), Some(false)),
                None,
                None,
                "agent",
            );
        }
    }

    // 3. Delegation edges and depth.
    if let Some((kind, name, _)) = exact.first() {
        let agents: Vec<(&String, &AgentDef)> = policy.agents.iter().collect();
        for (a, adef) in &agents {
            for (b, bdef) in &agents {
                if a == b {
                    continue;
                }
                let edge = adef.delegation.may_delegate_to.contains(b);
                let p = Principal::new(god.subject.clone(), b.as_str()).with_act([a.as_str()]);
                if !edge {
                    push(
                        format!("G-DELEG {a}->{b}"),
                        format!("{a} may not delegate to {b}"),
                        p,
                        act(kind, name, json!({})),
                        deny(Some("principal.delegation"), Some(false)),
                        None,
                        None,
                        "delegation",
                    );
                } else if bdef.delegation.max_depth == 0 {
                    push(
                        format!("G-DEPTH {a}->{b}"),
                        format!("{b} may not act under delegation"),
                        p,
                        act(kind, name, json!({})),
                        deny(Some("principal.delegation_depth"), Some(false)),
                        None,
                        None,
                        "delegation",
                    );
                }
            }
        }
        let unknown = Principal::new(god.subject.clone(), AGENT).with_act(["__eval_unknown_agent"]);
        push(
            "G-DELEG unknown actor".into(),
            "unknown agents in the chain are rejected".into(),
            unknown,
            act(kind, name, json!({})),
            deny(Some("principal.delegation"), Some(false)),
            None,
            None,
            "delegation",
        );

        // Strict argument parsing.
        push(
            "G-DUPKEY".into(),
            "duplicate JSON keys are rejected".into(),
            god.clone(),
            act(kind, name, json!({})),
            deny(Some("normalize.args"), None),
            None,
            Some(r#"{"x":"a","x":"b"}"#.into()),
            "args",
        );
    }

    // 4. Unknown actions and look-alike names.
    if catalog.resolve(&ActionKind::Tool, "eval.not_in_catalog").is_none() {
        push(
            "G-UNTAGGED".into(),
            "actions without catalog entry are denied".into(),
            god.clone(),
            Action::tool("eval.not_in_catalog", json!({})),
            deny(Some("catalog.untagged"), Some(false)),
            None,
            None,
            "catalog",
        );
    }
    for (kind, name, _) in &exact {
        if catalog.normalize_mode(kind) != agent_scope_core::catalog::NormalizeMode::Name {
            continue;
        }
        if let Some(h) = homoglyph(name) {
            push(
                format!("G-HOMOGLYPH {kind}:{name}"),
                format!("look-alike of {name}"),
                god.clone(),
                Action::new(kind.clone(), h, json!({})),
                deny(Some("normalize.name"), Some(false)),
                None,
                None,
                "names",
            );
        }
    }

    // 5. Argument constraints: missing, mistyped, invisible characters.
    for r in base.rules() {
        let target = exact.iter().find(|(k, n, _)| r.applies_to(catalog, k, n));
        let Some((kind, name, _)) = target else { continue };
        let mut seen = BTreeSet::new();
        for (path, op) in r.cond.arg_checks() {
            if path.contains('.') || !seen.insert((path.clone(), format!("{op:?}").chars().take(8).collect::<String>())) {
                continue;
            }
            let id = |what: &str| format!("G-ARG {} {path} {what}", r.id);
            push(
                id("missing"),
                format!("{} without `{path}`", r.id),
                god.clone(),
                act(kind, name, json!({})),
                deny(None, None),
                None,
                None,
                "args",
            );
            let wrong = match op {
                Op::Min(_) | Op::Max(_) | Op::NotInRange(..) => Some(json!("1")),
                Op::Equals(_) | Op::In(_) | Op::Glob(_) | Op::Regex(_) | Op::Sql(_) => Some(json!(12345)),
                Op::Custom(_) => None,
            };
            if let Some(w) = wrong {
                push(
                    id("wrong-type"),
                    format!("{} with mistyped `{path}`", r.id),
                    god.clone(),
                    act(kind, name, json!({ path.clone(): w })),
                    deny(None, None),
                    None,
                    None,
                    "args",
                );
            }
            let invisible = match op {
                Op::Equals(Operand::Placeholder(_)) | Op::In(Operand::Placeholder(_)) => Some(format!("{VALUE}\u{200b}")),
                Op::Equals(Operand::Literal(Value::String(s))) => Some(format!("{s}\u{200b}")),
                Op::In(Operand::Literal(Value::Array(a))) => a.first().and_then(Value::as_str).map(|s| format!("{s}\u{200b}")),
                _ => None,
            };
            if let Some(v) = invisible {
                push(
                    id("invisible"),
                    format!("{} with zero-width space in `{path}`", r.id),
                    god.clone(),
                    act(kind, name, json!({ path.clone(): v })),
                    deny(None, None),
                    None,
                    None,
                    "args",
                );
            }
        }
    }

    // 6. Kill switch and service subjects.
    for (kind, name, _) in exact.iter().filter(|(k, n, _)| catalog.resolve(k, n).is_some_and(|r| r.sensitivity == Sensitivity::Write)) {
        let ctx = Context { kill_switch: KillSwitch::Writes, ..Default::default() };
        push(
            format!("G-KILL {kind}:{name}"),
            "writes are blocked by the kill switch".into(),
            god.clone(),
            act(kind, name, json!({})),
            deny(Some("kill_switch"), Some(false)),
            Some(ctx),
            None,
            "kill_switch",
        );
    }
    if policy.service_subjects == ServiceSubjects::Deny {
        if let Some((kind, name, _)) = exact.first() {
            let svc = Principal::new(Subject::service("__eval_service__").with_roles([ALL]), AGENT);
            push(
                "G-SERVICE".into(),
                "tokens without a user are rejected".into(),
                svc,
                act(kind, name, json!({})),
                deny(Some("principal.service_subject"), Some(false)),
                None,
                None,
                "principal",
            );
        }
    }

    let engine = Engine::builder().policy(aug).catalog(catalog.clone()).lock(lock.cloned()).build().map_err(|e| e.to_string())?;
    Ok(Generated { engine, suite: Suite { suite: "generated".into(), description: None, principals: BTreeMap::new(), cases } })
}
