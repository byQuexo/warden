#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_warden"))
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(cmd: &mut Command) -> (i32, String) {
    let out = cmd.output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

#[test]
fn lint_and_eval_the_reference_policy() {
    let acme = root().join("examples/acme");
    let (code, out) = run(bin().current_dir(&acme).arg("lint").arg("--strict"));
    assert_eq!(code, 0, "{out}");
    let (code, out) =
        run(bin().current_dir(&acme).args(["eval", "--suite", "eval/reference.yaml", "--generate", "--mutate", "--coverage", "--gate"]));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("all gates green"));
}

#[test]
fn eval_gate_fails_on_a_weakened_policy() {
    let dir = tempfile::tempdir().unwrap();
    let acme = root().join("examples/acme");
    let policy = std::fs::read_to_string(acme.join("policy.yaml")).unwrap();
    // Drop the tenant-pinning rule: the mutation-style regression must be caught.
    let weakened = policy.replace("  - id: tenant-pinning\n", "  - id: tenant-pinning-disabled\n").replace(
        "    require: { arg: tenant, in: \"{subject.attrs.tenants}\" }\n\n  - id: update-tenant-pinning",
        "    require: always\n\n  - id: update-tenant-pinning",
    );
    assert_ne!(policy, weakened);
    std::fs::write(dir.path().join("policy.yaml"), weakened).unwrap();
    let (code, out) = run(bin().args([
        "eval",
        "--policy",
        dir.path().join("policy.yaml").to_str().unwrap(),
        "--catalog",
        acme.join("catalog.yaml").to_str().unwrap(),
        "--suite",
        acme.join("eval/reference.yaml").to_str().unwrap(),
        "--gate",
    ]));
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("scope_violation"));
}

#[test]
fn explain_prints_a_trace_and_exit_code_reflects_the_effect() {
    let acme = root().join("examples/acme");
    let principal = r#"{"subject":{"id":"henrik","roles":["hr-lead"],"attrs":{"org_unit":"hr"}},"agent":"acme-bot"}"#;
    let (code, out) = run(bin().current_dir(&acme).args([
        "explain",
        "--principal",
        principal,
        "--action",
        "tool:hr.get_salary",
        "--args",
        r#"{"unit":"sales"}"#,
    ]));
    assert_eq!(code, 1);
    assert!(out.contains("rule:   salary-only-own-unit"), "{out}");
    let (code, _) = run(bin().current_dir(&acme).args([
        "explain",
        "--principal",
        principal,
        "--action",
        "tool:hr.get_salary",
        "--args",
        r#"{"unit":"hr"}"#,
    ]));
    assert_eq!(code, 0);
}

#[test]
fn init_creates_a_working_starter_policy() {
    let dir = tempfile::tempdir().unwrap();
    let (code, out) = run(bin().arg("init").arg(dir.path()));
    assert_eq!(code, 0, "{out}");
    let (code, out) =
        run(bin().current_dir(dir.path()).args(["eval", "--suite", "scenarios.yaml", "--generate", "--mutate", "--coverage", "--gate"]));
    assert_eq!(code, 0, "{out}");
}

#[test]
fn audit_keygen_and_dev_token() {
    let (code, out) = run(bin().args(["audit", "keygen"]));
    assert_eq!(code, 0);
    assert!(out.contains("AUDIT_SIGNING_KEY=") && out.contains("AUDIT_PUBLIC_KEY="));

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("sts.yaml"), "issuer: http://127.0.0.1:9400\nkey_file: key.pem\n").unwrap();
    let (code, out) = run(bin().args([
        "dev",
        "token",
        "--config",
        dir.path().join("sts.yaml").to_str().unwrap(),
        "--subject",
        "sam",
        "--agent",
        "helpdesk-bot",
        "--roles",
        "support",
        "--audience",
        "http://127.0.0.1:8088/mcp",
    ]));
    assert_eq!(code, 0, "{out}");
    let jwt = out.lines().next().unwrap_or("").trim();
    assert_eq!(jwt.split('.').count(), 3, "expected a JWT, got {out}");
    assert!(dir.path().join("key.pem").exists());
}
