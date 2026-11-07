#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `approve_by: subject`: the user confirms an action an agent takes in their name.

use serde_json::json;
use warden_core::*;

const CATALOG: &str = r#"
version: 1
tool:
  crm.list_deals:  { scopes: [crm:read] }
  crm.update_deal: { scopes: [crm:write], sensitivity: write }
"#;

const POLICY: &str = r#"
version: 1
roles:
  sales: [crm:read, crm:write]
agents:
  bot: { max: [crm:read, crm:write] }
rules:
  - id: big-deals
    match: { kind: tool, name: crm.update_deal }
    approve_if: { arg: amount, min: 50000 }
  - id: confirm-writes
    match: { sensitivity: write }
    approve_if: always
    approve_by: subject
"#;

fn engine(policy: &str) -> Result<Engine, BuildError> {
    Engine::builder().policy_yaml(policy).catalog_yaml(CATALOG).build()
}

fn sven() -> Principal {
    Principal::new(Subject::user("sven").with_roles(["sales"]), "bot")
}

#[test]
fn writes_are_held_for_the_subjects_confirmation() {
    let e = engine(POLICY).unwrap();
    let d = e.check(&sven(), &Action::tool("crm.update_deal", json!({"amount": 1000})), &Context::default());
    assert_eq!(d.effect, Effect::RequireApproval);
    assert_eq!(d.rule, "confirm-writes");
    assert!(e.approved_by_subject("confirm-writes"));
    // Reads are untouched.
    let r = e.check(&sven(), &Action::tool("crm.list_deals", json!({})), &Context::default());
    assert_eq!(r.effect, Effect::Allow);
}

#[test]
fn an_earlier_approval_by_others_takes_precedence() {
    let e = engine(POLICY).unwrap();
    let d = e.check(&sven(), &Action::tool("crm.update_deal", json!({"amount": 80000})), &Context::default());
    assert_eq!(d.effect, Effect::RequireApproval);
    assert_eq!(d.rule, "big-deals");
    assert!(!e.approved_by_subject("big-deals"));
}

#[test]
fn approve_by_round_trips_and_defaults_to_others() {
    let e = engine(POLICY).unwrap();
    let rules = &e.policy().rules;
    assert_eq!(rules[0].approve_by, ApproveBy::Others);
    assert_eq!(rules[1].approve_by, ApproveBy::Subject);
    let yaml = serde_norway::to_string(e.policy()).unwrap();
    assert_eq!(yaml.matches("approve_by").count(), 1, "the default is not written out:\n{yaml}");
}

#[test]
fn approve_by_only_on_approval_rules() {
    let bad = POLICY.replace("approve_if: always\n    approve_by: subject", "deny_if: always\n    approve_by: subject");
    let err = engine(&bad).err().expect("must not build");
    assert!(format!("{err}").contains("approve_by"), "{err}");
}
