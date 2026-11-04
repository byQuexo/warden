//! Conformance vectors (spec/vectors/manifest.yaml). The TypeScript package runs the same files.

use std::path::{Path, PathBuf};

use agent_scope_core::{principal_from_claims, Engine, IdentityConfig};
use agent_scope_eval::generate::generate;
use agent_scope_eval::{run_cases, Suite};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Manifest {
    decision_suites: Vec<SuiteRef>,
    token_vectors: String,
}

#[derive(Deserialize)]
struct SuiteRef {
    policy: String,
    catalog: String,
    suite: String,
}

#[derive(Deserialize)]
struct TokenVectors {
    identity: String,
    cases: Vec<TokenCase>,
}

#[derive(Deserialize)]
struct TokenCase {
    id: String,
    now: i64,
    claims: Value,
    expect: Value,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn manifest() -> Manifest {
    serde_norway::from_str(&read(&root().join("spec/vectors/manifest.yaml"))).unwrap()
}

#[test]
fn decision_vectors() {
    let mut total = 0;
    for s in manifest().decision_suites {
        let engine = Engine::builder().policy_yaml(&read(&root().join(&s.policy))).catalog_yaml(&read(&root().join(&s.catalog))).build().unwrap();
        let suite = Suite::load(&root().join(&s.suite)).unwrap();
        let failed: Vec<String> = run_cases(&engine, &suite)
            .into_iter()
            .filter(|r| !r.passed)
            .map(|r| format!("{}/{}: expected {:?}, got {:?}", r.suite, r.id, r.expect, r.actual))
            .collect();
        assert!(failed.is_empty(), "{failed:#?}");
        total += suite.cases.len();

        // Generated attacks must be denied for every vector policy as well.
        let g = generate(engine.policy(), engine.catalog(), None).unwrap();
        let gen_failed: Vec<String> = run_cases(&g.engine, &g.suite).into_iter().filter(|r| !r.passed).map(|r| format!("{} -> {:?}", r.id, r.actual)).collect();
        assert!(gen_failed.is_empty(), "{}: {gen_failed:#?}", s.suite);
    }
    assert!(total >= 60, "only {total} decision vectors");
}

#[test]
fn token_vectors() {
    let m = manifest();
    let v: TokenVectors = serde_norway::from_str(&read(&root().join(m.token_vectors))).unwrap();
    let cfg = IdentityConfig::from_yaml_str(&v.identity).unwrap();
    for c in v.cases {
        let got = principal_from_claims(&c.claims, &cfg, c.now);
        match (c.expect.get("ok"), c.expect.get("error").and_then(Value::as_str), got) {
            (Some(ok), None, Ok(p)) => {
                let sorted = |v: &Value| {
                    let mut x: Vec<String> = v.as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
                    x.sort();
                    x
                };
                assert_eq!(p.subject.id, ok["subject"].as_str().unwrap(), "{}", c.id);
                assert_eq!(serde_json::to_value(p.subject.kind).unwrap(), ok["kind"], "{}", c.id);
                assert_eq!(p.agent, ok["agent"].as_str().unwrap(), "{}", c.id);
                assert_eq!(p.subject.roles.iter().cloned().collect::<Vec<_>>(), sorted(&ok["roles"]), "{}", c.id);
                assert_eq!(p.token_scopes.clone().unwrap_or_default().into_iter().collect::<Vec<_>>(), sorted(&ok["scopes"]), "{}", c.id);
                assert_eq!(serde_json::to_value(&p.act).unwrap(), ok["act"], "{}", c.id);
                if let Some(Value::Object(attrs)) = ok.get("attrs") {
                    for (k, want) in attrs {
                        assert_eq!(serde_json::to_value(p.subject.attrs.get(k)).unwrap(), *want, "{} attr {k}", c.id);
                    }
                }
            }
            (None, Some(code), Err(e)) => assert_eq!(e.code(), code, "{}", c.id),
            (_, _, got) => panic!("{}: expected {}, got {got:?}", c.id, c.expect),
        }
    }
}
