#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The committed JSON Schemas are current, every shipped example validates against them,
//! and they catch the mistakes the parsers catch (unknown keys, wrong types).

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema(name: &str) -> jsonschema::Validator {
    let text = std::fs::read_to_string(root().join(format!("spec/schema/{name}.schema.json"))).unwrap();
    jsonschema::validator_for(&serde_json::from_str::<Value>(&text).unwrap()).unwrap()
}

fn load(path: &Path) -> Value {
    serde_norway::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn errors(v: &jsonschema::Validator, doc: &Value) -> Vec<String> {
    v.iter_errors(doc).map(|e| format!("{} at {}", e, e.instance_path())).collect()
}

fn schema_for_file(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    let in_eval = path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "eval");
    Some(match name {
        "policy.yaml" => "policy",
        "catalog.yaml" => "catalog",
        "identity.yaml" => "identity",
        "gateway.yaml" => "gateway",
        "sts.yaml" => "sts",
        "catalog.lock" => "lock",
        "scenarios.yaml" => "suite",
        _ if in_eval => "suite",
        _ => return None,
    })
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn committed_schemas_are_up_to_date() {
    let out = Command::new(env!("CARGO_BIN_EXE_warden"))
        .args(["schema", "--check", "--out", root().join("spec/schema").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn every_example_validates() {
    let mut files = Vec::new();
    walk(&root().join("examples"), &mut files);
    let mut checked = 0;
    for f in files {
        let Some(name) = schema_for_file(&f) else { continue };
        let errs = errors(&schema(name), &load(&f));
        assert!(errs.is_empty(), "{} against {name}.schema.json:\n{}", f.display(), errs.join("\n"));
        checked += 1;
    }
    assert!(checked >= 15, "only {checked} example files found");
}

#[test]
fn schemas_reject_typos_and_wrong_types() {
    let bad = |name: &str, yaml: &str| {
        let doc: Value = serde_norway::from_str(yaml).unwrap();
        assert!(!errors(&schema(name), &doc).is_empty(), "{name} accepted:\n{yaml}");
    };
    bad("policy", "version: 1\nagnets: {}\n");
    bad("catalog", "version: 1\ntool:\n  a.b: { scope: [x] }\n");
    bad("catalog", "version: 1\ntool:\n  a.b: { scopes: [x], sensitivity: dangerous }\n");
    bad("catalog", "tool: {}\n");
    bad("identity", "version: 1\nissuers: [{ issuer: x }]\n");
    bad("sts", "issuer: https://x\nkey_file: k.pem\nclients: { a: { secret_env: A, roels: [] } }\n");
    bad("lock", "version: 1\npins: { tool: { a: 1 } }\n");
}

#[test]
fn print_one_schema() {
    let out = Command::new(env!("CARGO_BIN_EXE_warden")).args(["schema", "policy"]).output().unwrap();
    assert!(out.status.success());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["title"], "Warden policy");
    let out = Command::new(env!("CARGO_BIN_EXE_warden")).args(["schema", "nope"]).output().unwrap();
    assert!(!out.status.success());
}
