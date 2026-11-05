#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `subset_of` for list arguments.

use serde_json::json;
use warden_core::*;

const CATALOG: &str = r#"
version: 1
tool:
  docs.search:   { scopes: [docs:read] }
  crm.get_deal:  { scopes: [crm:read] }
  crm.update_deal: { scopes: [crm:write], sensitivity: write }
"#;

const POLICY: &str = r#"
version: 1
roles:
  sales: [docs:read, crm:read, crm:write]
agents:
  bot: { max: [docs:read, crm:read, crm:write] }
rules:
  - id: docs-in-scope
    match: { kind: tool, name: docs.search }
    require: { arg: doc_ids, subset_of: "{subject.attrs.doc_scope}" }
  - id: flag-test-sessions
    match: { kind: tool, name: crm.get_deal }
    approve_if: { context: impersonation, equals: true }
"#;

fn engine() -> Engine {
    Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap()
}

fn sven() -> Principal {
    Principal::new(
        Subject::user("sven").with_roles(["sales"]).with_attr("doc_scope", AttrValue::List(vec!["handbook".into(), "pricing".into()])),
        "bot",
    )
}

fn docs(ids: serde_json::Value) -> Decision {
    engine().check(&sven(), &Action::tool("docs.search", json!({ "q": "x", "doc_ids": ids })), &Context::default())
}

#[test]
fn subset_of_allows_only_lists_inside_the_attribute() {
    assert_eq!(docs(json!(["handbook"])).effect, Effect::Allow);
    assert_eq!(docs(json!(["handbook", "pricing"])).effect, Effect::Allow);
    assert_eq!(docs(json!([])).effect, Effect::Allow, "an empty list is a subset");
    let d = docs(json!(["handbook", "salaries"]));
    assert_eq!((d.effect, d.rule.as_str()), (Effect::Deny, "docs-in-scope"));
}

#[test]
fn subset_of_unknowns_deny() {
    assert_eq!(docs(json!("handbook")).effect, Effect::Deny, "a string is not a list");
    assert_eq!(docs(json!([1])).effect, Effect::Deny, "non-string element");
    assert_eq!(docs(json!(["hand\u{200b}book"])).effect, Effect::Deny, "invisible character");
    let missing = engine().check(&sven(), &Action::tool("docs.search", json!({ "q": "x" })), &Context::default());
    assert_eq!(missing.effect, Effect::Deny);
    let no_attr = Principal::new(Subject::user("x").with_roles(["sales"]), "bot");
    let d = engine().check(&no_attr, &Action::tool("docs.search", json!({ "doc_ids": [] })), &Context::default());
    assert_eq!(d.effect, Effect::Deny, "missing attribute is unknown");
}

#[test]
fn subset_of_rejects_scalars_at_compile_time() {
    let bad = POLICY.replace("\"{subject.attrs.doc_scope}\"", "handbook");
    assert!(Engine::builder().policy_yaml(&bad).catalog_yaml(CATALOG).build().is_err());
}
