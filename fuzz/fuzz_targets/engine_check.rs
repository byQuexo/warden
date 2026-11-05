#![no_main]
//! Arbitrary actions against the devtools policy: the engine never panics, and anything
//! that is not in the catalog is denied.
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use warden_core::{Action, ActionKind, AttrValue, Context, Effect, Engine, Principal, Subject};

const POLICY: &str = include_str!("../../examples/devtools/policy.yaml");
const CATALOG: &str = include_str!("../../examples/devtools/catalog.yaml");

fn engine() -> &'static Engine {
    static E: OnceLock<Engine> = OnceLock::new();
    E.get_or_init(|| Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().expect("policy"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let (name, args) = s.split_once('\n').unwrap_or((s, "{}"));
    let Ok(args) = serde_json::from_str::<serde_json::Value>(args) else { return };
    let p = Principal::new(
        Subject::user("fuzz").with_roles(["maintainer"]).with_attr("orgs", AttrValue::List(vec!["acme-dev".into()])),
        "ops-agent",
    );
    for kind in [ActionKind::Tool, ActionKind::Resource, ActionKind::Prompt] {
        let d = engine().check(&p, &Action::new(kind.clone(), name, args.clone()), &Context::default());
        if engine().catalog().resolve(&kind, name).is_none() {
            assert_eq!(d.effect, Effect::Deny);
        }
    }
});
