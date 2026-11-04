#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use warden_core::constraint::Cond;
use warden_core::Engine;
use warden_eval::generate::generate;
use warden_eval::mutation::mutate;
use warden_eval::{run_cases, EvalReport, GateConfig, Suite};

const POLICY: &str = include_str!("../../../examples/acme/policy.yaml");
const CATALOG: &str = include_str!("../../../examples/acme/catalog.yaml");
const SUITE: &str = include_str!("../../../examples/acme/eval/reference.yaml");

fn engine() -> Engine {
    Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap()
}

#[test]
fn reference_suite_passes_with_full_coverage_and_no_surviving_mutants() {
    let e = engine();
    let suite = Suite::from_yaml_str(SUITE).unwrap();
    let results = run_cases(&e, &suite);
    for r in results.iter().filter(|r| !r.passed) {
        println!("FAILED {} expected {:?} got {:?}", r.id, r.expect, r.actual);
    }
    let mutants = mutate(e.policy(), e.catalog(), None, std::slice::from_ref(&suite)).unwrap();
    let rules: Vec<(String, bool)> = e.rules().iter().map(|r| (r.id.clone(), !matches!(r.cond, Cond::Always))).collect();
    let report =
        EvalReport::build(e.version(), &rules, results, Some(mutants), &GateConfig { require_rule_coverage: true, baseline: None });
    println!("{}", report.to_markdown());
    assert!(report.passed(), "gates failed");
}

#[test]
fn generated_attacks_all_denied() {
    let e = engine();
    let g = generate(e.policy(), e.catalog(), None).unwrap();
    assert!(g.suite.cases.len() > 50, "generator produced only {} cases", g.suite.cases.len());
    let results = run_cases(&g.engine, &g.suite);
    let failed: Vec<_> = results.iter().filter(|r| !r.passed).map(|r| format!("{} -> {:?}", r.id, r.actual)).collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

#[test]
fn a_broken_policy_is_caught() {
    // Widen the sales role: the reference suite must notice (scope_violation > 0).
    let broken = POLICY.replace(
        "sales-rep:   [crm:read, crm:write, \"docs:sales\"]",
        "sales-rep:   [crm:read, crm:write, crm:export, \"docs:sales\", \"docs:it\"]",
    );
    let e = Engine::builder().policy_yaml(&broken).catalog_yaml(CATALOG).build().unwrap();
    let suite = Suite::from_yaml_str(SUITE).unwrap();
    let report = EvalReport::build(e.version(), &[], run_cases(&e, &suite), None, &GateConfig::default());
    assert!(!report.passed());
    let g = report.gates.iter().find(|g| g.name == "scope_violation").unwrap();
    assert_ne!(g.value, "0");
}
