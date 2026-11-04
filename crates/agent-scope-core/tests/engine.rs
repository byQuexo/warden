use std::sync::Arc;

use agent_scope_core::constraint::Tri;
use agent_scope_core::*;
use serde_json::json;

const POLICY: &str = include_str!("../../../examples/acme/policy.yaml");
const CATALOG: &str = include_str!("../../../examples/acme/catalog.yaml");

fn engine() -> Engine {
    Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap()
}

fn henrik() -> Principal {
    Principal::new(
        Subject::user("henrik").with_roles(["hr-lead"]).with_attr("org_unit", AttrValue::String("hr".into())),
        "acme-bot",
    )
}

fn sven() -> Principal {
    Principal::new(
        Subject::user("sven").with_roles(["sales-rep"]).with_attr("tenants", AttrValue::List(vec!["dach".into()])),
        "acme-bot",
    )
}

#[test]
fn reference_policy_has_no_lint_errors() {
    let e = engine();
    for w in e.warnings() {
        println!("{w}");
    }
    assert!(e.version().starts_with("sha256:"));
}

#[test]
fn rule_restricts_what_scope_allows() {
    let e = engine();
    let ctx = Context::default();
    let own = e.check(&henrik(), &Action::tool("hr.get_salary", json!({"unit": "hr"})), &ctx);
    assert_eq!(own.effect, Effect::Allow, "{}", own.render());
    let other = e.check(&henrik(), &Action::tool("hr.get_salary", json!({"unit": "sales"})), &ctx);
    assert_eq!(other.effect, Effect::Deny);
    assert_eq!(other.rule, "salary-only-own-unit");
    assert_eq!(other.model_message, "This action is not permitted.");
}

#[test]
fn missing_or_mistyped_arguments_deny() {
    let e = engine();
    let ctx = Context::default();
    for args in [json!({"tenant": "dach"}), json!({"tenant": "dach", "amount": "80000"})] {
        let d = e.check(&sven(), &Action::tool("crm.update_deal", args), &ctx);
        assert_eq!(d.effect, Effect::Deny, "{}", d.render());
    }
    let d = e.check(&sven(), &Action::tool("crm.update_deal", json!({"tenant": "dach", "amount": 8e4})), &ctx);
    assert_eq!(d.effect, Effect::RequireApproval);
}

#[test]
fn invisible_characters_deny() {
    let e = engine();
    let d = e.check(&sven(), &Action::tool("crm.list_deals", json!({"tenant": "dach\u{200b}"})), &Context::default());
    assert_eq!(d.effect, Effect::Deny);
}

#[test]
fn visibility_ignores_argument_rules_but_not_scopes() {
    let e = engine();
    let ctx = Context::default();
    let tools = ["hr.get_salary", "hr.search_employees", "crm.list_deals", "hr.delete_employee"];
    assert_eq!(e.filter(&henrik(), &ActionKind::Tool, tools, &ctx), vec!["hr.get_salary", "hr.search_employees"]);
    let hanna = Principal::new(Subject::user("hanna").with_roles(["hr-member"]), "acme-bot");
    assert_eq!(e.filter(&hanna, &ActionKind::Tool, tools, &ctx), vec!["hr.search_employees"]);
}

#[test]
fn delegation_intersects_every_actor() {
    let e = engine();
    let ctx = Context::default();
    let args = json!({"tenant": "dach", "amount": 10});
    // research holds no crm:write, so a chain through research can never write.
    let p = sven().with_act(["acme-research"]).with_agent("acme-action");

    let d = e.check(&p, &Action::tool("crm.update_deal", args.clone()), &ctx);
    assert_eq!(d.rule, "scope.missing", "{}", d.render());
    // bot → action is a valid edge and both hold crm:write.
    let p = sven().with_act(["acme-bot"]).with_agent("acme-action");
    assert_eq!(e.check(&p, &Action::tool("crm.update_deal", args.clone()), &ctx).effect, Effect::Allow);
    // action → bot is not an allowed edge.
    let p = sven().with_act(["acme-action"]);
    assert_eq!(e.check(&p, &Action::tool("crm.update_deal", args), &ctx).rule, "principal.delegation");
}

#[test]
fn lock_pins_definitions() {
    let mut lock = Lock::new();
    lock.pin("tool", "crm.list_deals", "sha256:aaa");
    let e = Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).lock(Some(lock)).build().unwrap();
    let ctx = Context::default();
    let ok = Action::tool("crm.list_deals", json!({"tenant": "dach"})).with_definition_hash("sha256:aaa");
    assert_eq!(e.check(&sven(), &ok, &ctx).effect, Effect::Allow);
    let changed = Action::tool("crm.list_deals", json!({"tenant": "dach"})).with_definition_hash("sha256:bbb");
    assert_eq!(e.check(&sven(), &changed, &ctx).rule, "catalog.unpinned");
    let unpinned = Action::tool("crm.update_deal", json!({"tenant": "dach", "amount": 1}));
    assert_eq!(e.check(&sven(), &unpinned, &ctx).rule, "catalog.unpinned");
}

#[test]
fn kill_switch() {
    let e = engine();
    let read = Action::tool("crm.list_deals", json!({"tenant": "dach"}));
    let write = Action::tool("crm.update_deal", json!({"tenant": "dach", "amount": 1}));
    let writes = Context { kill_switch: KillSwitch::Writes, ..Default::default() };
    assert_eq!(e.check(&sven(), &read, &writes).effect, Effect::Allow);
    assert_eq!(e.check(&sven(), &write, &writes).rule, "kill_switch");
    let all = Context { kill_switch: KillSwitch::All, ..Default::default() };
    assert_eq!(e.check(&sven(), &read, &all).rule, "kill_switch");
}

#[test]
fn panicking_custom_constraint_fails_closed() {
    let catalog = "version: 1\ntool:\n  a.b: { scopes: [x:y] }\n";
    let policy = r#"
version: 1
roles: { r: ["x:y"] }
agents: { bot: { max: ["x:y"] } }
rules:
  - { id: boom, match: { name: a.b }, require: { arg: v, custom: explode } }
"#;
    let explode = |_: &serde_json::Value, _: &Principal, _: &Context| -> Tri { panic!("boom") };
    let e = Engine::builder().policy_yaml(policy).catalog_yaml(catalog).custom("explode", Arc::new(explode)).build().unwrap();
    let p = Principal::new(Subject::user("u").with_roles(["r"]), "bot");
    let d = e.check(&p, &Action::tool("a.b", json!({"v": 1})), &Context::default());
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.rule, "internal.error");
}

#[test]
fn lint_rejects_unsafe_policies() {
    let catalog = "version: 1\ntool:\n  a.b: { scopes: [x:y] }\n";
    for bad in [
        "version: 1\ndefaults: { effect: allow }",
        "version: 1\nroles: { r: ['*'] }",
        "version: 1\nrules: [{ id: r, match: { name: a.b }, require: { arg: v, regex: 'abc' } }]",
        "version: 1\nrules: [{ id: r, match: { name: a.b }, require: { arg: v, equals: '{args.x}' } }]",
        "version: 1\nrules: [{ id: r, match: { name: nothing.here }, require: always }]",
        "version: 1\nrules: [{ id: r, match: { name: a.b }, require: always, deny_if: always }]",
    ] {
        assert!(Engine::builder().policy_yaml(bad).catalog_yaml(catalog).build().is_err(), "should reject: {bad}");
    }
}
