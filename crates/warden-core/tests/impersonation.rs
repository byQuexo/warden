#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Read-only impersonation ("test as user").

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

#[test]
fn impersonated_principals_cannot_write() {
    let e = engine();
    let ines_as_sven = sven().impersonated_by("ines");
    let write = e.check(&ines_as_sven, &Action::tool("crm.update_deal", json!({ "deal_id": "d-1" })), &Context::default());
    assert_eq!((write.effect, write.rule.as_str()), (Effect::Deny, "impersonation.read_only"));
    // The same write as Sven himself is allowed.
    let real = e.check(&sven(), &Action::tool("crm.update_deal", json!({ "deal_id": "d-1" })), &Context::default());
    assert_eq!(real.effect, Effect::Allow);
    // Reads work and the trace records the operator.
    let read = e.explain(&ines_as_sven, &Action::tool("docs.search", json!({ "doc_ids": ["pricing"] })), &Context::default());
    assert_eq!(read.effect, Effect::Allow);
    assert!(read.render().contains("by=ines"), "{}", read.render());
}

#[test]
fn rules_see_impersonation_in_context() {
    let e = engine();
    let a = Action::tool("crm.get_deal", json!({ "deal_id": "d-1" }));
    assert_eq!(e.check(&sven().impersonated_by("ines"), &a, &Context::default()).effect, Effect::RequireApproval);
    // Without impersonation the context value is missing, so the approve_if is unknown → deny.
    // That is the documented "unknown denies" behaviour; real policies use deny_if on writes.
    assert_eq!(e.check(&sven(), &a, &Context::default()).effect, Effect::Deny);
}

#[test]
fn impersonation_survives_serde() {
    let p = sven().impersonated_by("ines");
    let back: Principal = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
    assert_eq!(back.impersonated_by.as_deref(), Some("ines"));
    let plain = serde_json::to_value(sven()).unwrap();
    assert!(plain.get("impersonated_by").is_none(), "field is omitted when unset");
}
