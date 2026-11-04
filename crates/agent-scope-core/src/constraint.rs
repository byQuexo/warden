//! Rule conditions: a fixed, script-free constraint language.
//!
//! ```yaml
//! always
//! { arg: amount, min: 50000 }
//! { arg: unit, equals: "{subject.attrs.org_unit}" }
//! { arg: tenant, in: "{subject.attrs.tenants}" }
//! { context: hour_utc, not_in_range: [6, 20] }
//! { arg: sql, sql: { dialect: postgres, tables_allow: [deals] } }
//! { all: [ …, … ] }   { any: [ …, … ] }
//! ```
//!
//! Evaluation is three-valued. A missing argument, a type mismatch, an invisible character or
//! an unresolvable placeholder yields [`Tri::Unknown`], and **Unknown always denies**,
//! whatever kind of rule the condition belongs to.

use std::collections::BTreeMap;
use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::engine::CustomConstraint;
use crate::glob;
use crate::model::{Action, AttrValue, Context, Principal};
use crate::normalize::has_invisible_chars;
use crate::sql::SqlSpec;

#[derive(Clone, Debug, PartialEq)]
pub enum Tri {
    True,
    False,
    Unknown(String),
}

#[derive(Clone, Debug)]
pub enum Cond {
    Always,
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Check(Check),
}

#[derive(Clone, Debug)]
pub struct Check {
    pub source: Source,
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Source {
    Arg(Vec<String>),
    Context(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Placeholder {
    SubjectId,
    SubjectAttr(String),
    AgentId,
    Context(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Literal(Value),
    Placeholder(Placeholder),
}

#[derive(Clone, Debug)]
pub enum Op {
    Equals(Operand),
    In(Operand),
    Glob(String),
    Regex(Regex),
    Min(f64),
    Max(f64),
    NotInRange(f64, f64),
    Sql(SqlSpec),
    Custom(String),
}

impl Op {
    fn name(&self) -> &'static str {
        match self {
            Op::Equals(_) => "equals",
            Op::In(_) => "in",
            Op::Glob(_) => "glob",
            Op::Regex(_) => "regex",
            Op::Min(_) => "min",
            Op::Max(_) => "max",
            Op::NotInRange(..) => "not_in_range",
            Op::Sql(_) => "sql",
            Op::Custom(_) => "custom",
        }
    }
}

const OP_KEYS: &[&str] = &["equals", "in", "glob", "regex", "min", "max", "not_in_range", "sql", "custom"];

/// Compile a condition from its YAML/JSON form.
pub fn compile(v: &Value) -> Result<Cond, String> {
    match v {
        Value::String(s) if s == "always" => Ok(Cond::Always),
        Value::String(s) => Err(format!("unknown condition keyword `{s}` (did you mean `always`?)")),
        Value::Object(m) if m.contains_key("all") || m.contains_key("any") => {
            if m.len() != 1 {
                return Err("`all`/`any` must be the only key of a condition".into());
            }
            let (k, list) = m.iter().next().ok_or("empty condition")?;
            let Value::Array(items) = list else {
                return Err(format!("`{k}` must be a list of conditions"));
            };
            if items.is_empty() {
                return Err(format!("`{k}` must not be empty"));
            }
            let conds = items.iter().map(compile).collect::<Result<Vec<_>, _>>()?;
            Ok(if k == "all" { Cond::All(conds) } else { Cond::Any(conds) })
        }
        Value::Object(m) => {
            for k in m.keys() {
                if k != "arg" && k != "context" && !OP_KEYS.contains(&k.as_str()) {
                    return Err(format!("unknown condition key `{k}`"));
                }
            }
            let source = match (m.get("arg"), m.get("context")) {
                (Some(Value::String(a)), None) => {
                    if a.is_empty() {
                        return Err("`arg` must not be empty".into());
                    }
                    Source::Arg(a.split('.').map(str::to_string).collect())
                }
                (None, Some(Value::String(c))) => Source::Context(c.clone()),
                _ => return Err("a condition needs exactly one of `arg: <name>` or `context: <key>`".into()),
            };
            let mut ops = Vec::new();
            for key in OP_KEYS {
                if let Some(val) = m.get(*key) {
                    ops.push(compile_op(key, val)?);
                }
            }
            if ops.is_empty() {
                return Err("condition has no operator (equals, in, glob, regex, min, max, not_in_range, sql, custom)".into());
            }
            Ok(Cond::Check(Check { source, ops }))
        }
        _ => Err("a condition must be `always` or a mapping".into()),
    }
}

fn compile_op(key: &str, v: &Value) -> Result<Op, String> {
    let num = |v: &Value| v.as_f64().ok_or_else(|| format!("`{key}` must be a number"));
    Ok(match key {
        "equals" => {
            let o = operand(v)?;
            if matches!(o, Operand::Literal(Value::Array(_)) | Operand::Literal(Value::Object(_))) {
                return Err("`equals` takes a scalar; use `in` for lists".into());
            }
            Op::Equals(o)
        }
        "in" => {
            let o = operand(v)?;
            match &o {
                Operand::Literal(Value::Array(items)) if items.iter().all(Value::is_string) => {}
                Operand::Placeholder(_) => {}
                _ => return Err("`in` takes a list of strings or a list placeholder".into()),
            }
            Op::In(o)
        }
        "glob" => Op::Glob(v.as_str().ok_or("`glob` must be a string")?.to_string()),
        "regex" => {
            let p = v.as_str().ok_or("`regex` must be a string")?;
            if !(p.starts_with('^') && p.ends_with('$')) {
                return Err(format!("regex `{p}` must be anchored with ^…$"));
            }
            let re = RegexBuilder::new(p).size_limit(1 << 20).build().map_err(|e| format!("invalid regex `{p}`: {e}"))?;
            Op::Regex(re)
        }
        "min" => Op::Min(num(v)?),
        "max" => Op::Max(num(v)?),
        "not_in_range" => {
            let arr = v.as_array().filter(|a| a.len() == 2).ok_or("`not_in_range` must be [low, high]")?;
            Op::NotInRange(num(&arr[0])?, num(&arr[1])?)
        }
        "sql" => {
            let spec: SqlSpec = serde_json::from_value(v.clone()).map_err(|e| format!("`sql`: {e}"))?;
            spec.validate()?;
            Op::Sql(spec)
        }
        "custom" => Op::Custom(v.as_str().ok_or("`custom` must be a constraint name")?.to_string()),
        _ => return Err(format!("unknown operator `{key}`")),
    })
}

fn operand(v: &Value) -> Result<Operand, String> {
    if let Value::String(s) = v {
        if let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
            return Ok(Operand::Placeholder(placeholder(inner)?));
        }
    }
    Ok(Operand::Literal(v.clone()))
}

fn placeholder(p: &str) -> Result<Placeholder, String> {
    let valid_key = |k: &str| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    Ok(match p {
        "subject.id" => Placeholder::SubjectId,
        "agent.id" => Placeholder::AgentId,
        _ => {
            if let Some(k) = p.strip_prefix("subject.attrs.").filter(|k| valid_key(k)) {
                Placeholder::SubjectAttr(k.to_string())
            } else if let Some(k) = p.strip_prefix("context.").filter(|k| valid_key(k)) {
                Placeholder::Context(k.to_string())
            } else {
                return Err(format!(
                    "placeholder `{{{p}}}` is not allowed; use subject.id, subject.attrs.<key>, agent.id or context.<key> (never arguments)"
                ));
            }
        }
    })
}

pub struct Env<'a> {
    pub principal: &'a Principal,
    pub action: &'a Action,
    pub ctx: &'a Context,
    pub customs: &'a BTreeMap<String, Arc<dyn CustomConstraint>>,
}

impl Cond {
    pub fn eval(&self, env: &Env) -> Tri {
        match self {
            Cond::Always => Tri::True,
            Cond::All(cs) => {
                let mut all = true;
                for c in cs {
                    match c.eval(env) {
                        Tri::Unknown(r) => return Tri::Unknown(r),
                        Tri::False => all = false,
                        Tri::True => {}
                    }
                }
                if all {
                    Tri::True
                } else {
                    Tri::False
                }
            }
            Cond::Any(cs) => {
                let mut any = false;
                for c in cs {
                    match c.eval(env) {
                        Tri::Unknown(r) => return Tri::Unknown(r),
                        Tri::True => any = true,
                        Tri::False => {}
                    }
                }
                if any {
                    Tri::True
                } else {
                    Tri::False
                }
            }
            Cond::Check(c) => c.eval(env),
        }
    }

    /// True if the condition compares strings by equality/pattern (denylist smell for `deny_if`).
    pub fn uses_string_match(&self) -> bool {
        match self {
            Cond::Always => false,
            Cond::All(cs) | Cond::Any(cs) => cs.iter().any(Cond::uses_string_match),
            Cond::Check(c) => c.ops.iter().any(|o| {
                matches!(o, Op::Glob(_) | Op::Regex(_))
                    || matches!(o, Op::Equals(Operand::Literal(Value::String(_))) | Op::Equals(Operand::Placeholder(_)))
            }),
        }
    }

    pub fn custom_names(&self) -> Vec<String> {
        match self {
            Cond::Always => vec![],
            Cond::All(cs) | Cond::Any(cs) => cs.iter().flat_map(Cond::custom_names).collect(),
            Cond::Check(c) => c.ops.iter().filter_map(|o| if let Op::Custom(n) = o { Some(n.clone()) } else { None }).collect(),
        }
    }

    /// Argument names referenced by the condition (used by the eval generator).
    pub fn arg_checks(&self) -> Vec<(String, &Op)> {
        match self {
            Cond::Always => vec![],
            Cond::All(cs) | Cond::Any(cs) => cs.iter().flat_map(Cond::arg_checks).collect(),
            Cond::Check(c) => match &c.source {
                Source::Arg(path) => c.ops.iter().map(|o| (path.join("."), o)).collect(),
                Source::Context(_) => vec![],
            },
        }
    }

    pub fn placeholders(&self) -> Vec<Placeholder> {
        match self {
            Cond::Always => vec![],
            Cond::All(cs) | Cond::Any(cs) => cs.iter().flat_map(Cond::placeholders).collect(),
            Cond::Check(c) => c
                .ops
                .iter()
                .filter_map(|o| match o {
                    Op::Equals(Operand::Placeholder(p)) | Op::In(Operand::Placeholder(p)) => Some(p.clone()),
                    _ => None,
                })
                .collect(),
        }
    }
}

fn attr_to_value(a: &AttrValue) -> Value {
    match a {
        AttrValue::Bool(b) => Value::Bool(*b),
        AttrValue::Number(n) => serde_json::Number::from_f64(*n).map(Value::Number).unwrap_or(Value::Null),
        AttrValue::String(s) => Value::String(s.clone()),
        AttrValue::List(l) => Value::Array(l.iter().cloned().map(Value::String).collect()),
    }
}

impl Check {
    fn eval(&self, env: &Env) -> Tri {
        let value = match &self.source {
            Source::Arg(path) => {
                let mut cur = &env.action.args;
                for seg in path {
                    match cur.get(seg) {
                        Some(v) => cur = v,
                        None => return Tri::Unknown(format!("argument `{}` is missing", path.join("."))),
                    }
                }
                cur.clone()
            }
            Source::Context(k) => match env.ctx.values.get(k) {
                Some(a) => attr_to_value(a),
                None => return Tri::Unknown(format!("context value `{k}` is missing")),
            },
        };
        if value.is_null() {
            return Tri::Unknown("value is null".into());
        }
        let mut result = Tri::True;
        for op in &self.ops {
            match eval_op(op, &value, env) {
                Tri::True => {}
                Tri::False => result = Tri::False,
                u @ Tri::Unknown(_) => return u,
            }
        }
        result
    }
}

fn resolve(o: &Operand, env: &Env) -> Result<Value, String> {
    match o {
        Operand::Literal(v) => Ok(v.clone()),
        Operand::Placeholder(p) => match p {
            Placeholder::SubjectId => Ok(Value::String(env.principal.subject.id.clone())),
            Placeholder::AgentId => Ok(Value::String(env.principal.agent.clone())),
            Placeholder::SubjectAttr(k) => {
                env.principal.subject.attrs.get(k).map(attr_to_value).ok_or_else(|| format!("subject attribute `{k}` is missing"))
            }
            Placeholder::Context(k) => env.ctx.values.get(k).map(attr_to_value).ok_or_else(|| format!("context value `{k}` is missing")),
        },
    }
}

fn clean_str<'v>(v: &'v Value, op: &str) -> Result<&'v str, Tri> {
    match v {
        Value::String(s) if has_invisible_chars(s) => Err(Tri::Unknown(format!("`{op}`: value contains control or invisible characters"))),
        Value::String(s) => Ok(s),
        other => Err(Tri::Unknown(format!("`{op}` expects a string, got {}", type_name(other)))),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn number(v: &Value, op: &str) -> Result<f64, Tri> {
    v.as_f64().ok_or_else(|| Tri::Unknown(format!("`{op}` expects a number, got {}", type_name(v))))
}

fn tri(b: bool) -> Tri {
    if b {
        Tri::True
    } else {
        Tri::False
    }
}

fn eval_op(op: &Op, value: &Value, env: &Env) -> Tri {
    let r = (|| -> Result<Tri, Tri> {
        Ok(match op {
            Op::Equals(o) => {
                let expected = resolve(o, env).map_err(Tri::Unknown)?;
                match &expected {
                    Value::String(e) => tri(clean_str(value, "equals")? == e),
                    Value::Number(_) => tri(number(value, "equals")? == expected.as_f64().unwrap_or(f64::NAN)),
                    Value::Bool(b) => match value {
                        Value::Bool(v) => tri(v == b),
                        other => return Err(Tri::Unknown(format!("`equals` expects a bool, got {}", type_name(other)))),
                    },
                    other => return Err(Tri::Unknown(format!("`equals` operand resolved to {}", type_name(other)))),
                }
            }
            Op::In(o) => {
                let list = resolve(o, env).map_err(Tri::Unknown)?;
                let Value::Array(items) = list else {
                    return Err(Tri::Unknown("`in` operand did not resolve to a list".into()));
                };
                let s = clean_str(value, "in")?;
                tri(items.iter().any(|i| i.as_str() == Some(s)))
            }
            Op::Glob(p) => tri(glob::matches(p, clean_str(value, "glob")?, '/')),
            Op::Regex(re) => tri(re.is_match(clean_str(value, "regex")?)),
            Op::Min(m) => tri(number(value, "min")? >= *m),
            Op::Max(m) => tri(number(value, "max")? <= *m),
            Op::NotInRange(lo, hi) => {
                let n = number(value, "not_in_range")?;
                tri(n < *lo || n >= *hi)
            }
            Op::Sql(spec) => tri(spec.check(clean_str(value, "sql")?).is_ok()),
            Op::Custom(name) => match env.customs.get(name) {
                Some(c) => c.eval(value, env.principal, env.ctx),
                None => return Err(Tri::Unknown(format!("custom constraint `{name}` is not registered"))),
            },
        })
    })();
    match r {
        Ok(t) | Err(t) => t,
    }
}

/// Short description of an op for traces.
pub fn describe(op: &Op) -> &'static str {
    op.name()
}
