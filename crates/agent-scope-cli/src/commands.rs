use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_scope_core::constraint::Cond;
use agent_scope_core::json::{parse_strict, Limits};
use agent_scope_core::lint::Level;
use agent_scope_core::lock::definition_hash;
use agent_scope_core::normalize::normalize_name;
use agent_scope_core::{Action, ActionKind, Context, Effect, Engine, IdentityConfig, Lock, Principal};
use agent_scope_eval::generate::generate;
use agent_scope_eval::mutation::mutate;
use agent_scope_eval::{run_cases, EvalReport, GateConfig, Suite};
use agent_scope_gateway::config::GatewayConfig;
use agent_scope_identity::{ClientDef, Sts, StsConfig};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::PolicyArgs;

fn read(p: &Path) -> Result<String, String> {
    std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
}

fn write(p: &Path, s: &str) -> Result<(), String> {
    std::fs::write(p, s).map_err(|e| format!("{}: {e}", p.display()))
}

fn load_lock(p: Option<&Path>) -> Result<Option<Lock>, String> {
    p.map(|p| read(p).and_then(|s| Lock::from_json_str(&s))).transpose()
}

pub fn load_engine(f: &PolicyArgs) -> Result<Engine, String> {
    Engine::builder()
        .policy_yaml(&read(&f.policy)?)
        .catalog_yaml(&read(&f.catalog)?)
        .lock(load_lock(f.lock.as_deref())?)
        .build()
        .map_err(|e| e.to_string())
}

const MIN_POLICY: &str = include_str!("../../../examples/minimal/policy.yaml");
const MIN_CATALOG: &str = include_str!("../../../examples/minimal/catalog.yaml");
const MIN_IDENTITY: &str = include_str!("../../../examples/minimal/identity.yaml");
const MIN_SCENARIOS: &str = include_str!("../../../examples/minimal/scenarios.yaml");

pub fn init(dir: &Path) -> Result<i32, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    for (name, content) in
        [("policy.yaml", MIN_POLICY), ("catalog.yaml", MIN_CATALOG), ("identity.yaml", MIN_IDENTITY), ("scenarios.yaml", MIN_SCENARIOS)]
    {
        let p = dir.join(name);
        if p.exists() {
            println!("skip   {} (exists)", p.display());
        } else {
            write(&p, content)?;
            println!("create {}", p.display());
        }
    }
    println!("\nnext: agent-scope lint && agent-scope eval --suite scenarios.yaml --generate --mutate --coverage --gate");
    Ok(0)
}

pub fn lint(f: &PolicyArgs, identity: Option<&Path>, strict: bool) -> Result<i32, String> {
    let policy = agent_scope_core::Policy::from_yaml_str(&read(&f.policy)?).map_err(|e| format!("policy: {e}"))?;
    let catalog = agent_scope_core::Catalog::from_yaml_str(&read(&f.catalog)?).map_err(|e| format!("catalog: {e}"))?;
    load_lock(f.lock.as_deref())?;
    let (rules, mut findings) = agent_scope_core::engine::compile_rules(&policy);
    findings.extend(agent_scope_core::lint::lint(&policy, &catalog, &rules, &BTreeMap::new()));
    if let Some(i) = identity {
        if let Err(e) = IdentityConfig::from_yaml_str(&read(i)?) {
            findings.push(agent_scope_core::Finding::error("identity", e));
        }
    }
    for f in &findings {
        println!("{f}");
    }
    let errors = findings.iter().filter(|f| f.level == Level::Error).count();
    let warnings = findings.len() - errors;
    println!("\n{errors} error(s), {warnings} warning(s)");
    Ok(if errors > 0 || (strict && warnings > 0) { 1 } else { 0 })
}

fn json_arg(s: &str) -> Result<Value, String> {
    let text = match s.strip_prefix('@') {
        Some(path) => read(Path::new(path))?,
        None => s.to_string(),
    };
    parse_strict(&text, Limits::default()).map_err(|e| e.to_string())
}

pub fn explain(f: &PolicyArgs, principal: &str, action: &str, args: &str, context: Option<&str>, as_json: bool) -> Result<i32, String> {
    let engine = load_engine(f)?;
    let p: Principal = serde_json::from_value(json_arg(principal)?).map_err(|e| format!("principal: {e}"))?;
    let (kind, name) = action.split_once(':').ok_or("action must be `kind:name`")?;
    let kind: ActionKind = kind.parse()?;
    let mut a = Action::new(kind, name, json_arg(args)?);
    if let Some(Some(h)) = engine.lock().and_then(|l| l.pinned(a.kind.as_str(), name)) {
        a = a.with_definition_hash(h);
    }
    let ctx: Context = match context {
        Some(c) => serde_json::from_value(json_arg(c)?).map_err(|e| format!("context: {e}"))?,
        None => Context::default(),
    };
    let d = engine.explain(&p, &a, &ctx);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&d).unwrap_or_default());
    } else {
        print!("{}", d.render());
        println!("\nvisible to the model: {}", engine.visible(&p, &a, &ctx));
        println!("model sees: {}", if d.model_message.is_empty() { "(tool result)" } else { &d.model_message });
    }
    Ok(match d.effect {
        Effect::Allow => 0,
        _ => 1,
    })
}

pub struct EvalOpts {
    pub files: PolicyArgs,
    pub suites: Vec<PathBuf>,
    pub generate: bool,
    pub mutate: bool,
    pub coverage: bool,
    pub baseline: Option<PathBuf>,
    pub write_baseline: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub json: Option<PathBuf>,
    pub gate: bool,
}

pub fn eval(o: EvalOpts) -> Result<i32, String> {
    let engine = load_engine(&o.files)?;
    let suites: Vec<Suite> = o.suites.iter().map(|p| Suite::load(p)).collect::<Result<_, _>>()?;
    let mut results = Vec::new();
    for s in &suites {
        results.extend(run_cases(&engine, s));
    }
    if o.generate {
        let g = generate(engine.policy(), engine.catalog(), engine.lock())?;
        println!("generated {} attack cases", g.suite.cases.len());
        results.extend(run_cases(&g.engine, &g.suite));
    }
    let mutants = if o.mutate { Some(mutate(engine.policy(), engine.catalog(), engine.lock(), &suites)?) } else { None };
    let baseline = o
        .baseline
        .as_deref()
        .map(|p| read(p).and_then(|s| serde_json::from_str::<BTreeMap<String, String>>(&s).map_err(|e| e.to_string())))
        .transpose()?;
    let rules: Vec<(String, bool)> = engine.rules().iter().map(|r| (r.id.clone(), !matches!(r.cond, Cond::Always))).collect();
    let report = EvalReport::build(engine.version(), &rules, results, mutants, &GateConfig { require_rule_coverage: o.coverage, baseline });
    let md = report.to_markdown();
    println!("{md}");
    if let Some(p) = &o.report {
        write(p, &md)?;
    }
    if let Some(p) = &o.json {
        write(p, &serde_json::to_string_pretty(&report).unwrap_or_default())?;
    }
    if let Some(p) = &o.write_baseline {
        write(p, &serde_json::to_string_pretty(&report.baseline()).unwrap_or_default())?;
    }
    Ok(if o.gate && !report.passed() { 1 } else { 0 })
}

pub fn audit_verify(dir: &Path, pubkey: Option<&str>, max_unanchored: u64) -> Result<i32, String> {
    let pk = pubkey.map(agent_scope_audit::verifying_key_from_b64).transpose().map_err(|e| e.to_string())?;
    match agent_scope_audit::verify_dir(dir, pk.as_ref(), max_unanchored) {
        Ok(r) => {
            for (chain, c) in &r.chains {
                println!(
                    "✔ chain {chain}: {} events in {} file(s), {} signed checkpoint(s), {} unanchored",
                    c.events, c.files, c.checkpoints, c.unanchored_tail
                );
            }
            if pk.is_none() {
                println!("note: no --pubkey given; checkpoint signatures were not verified");
            }
            Ok(0)
        }
        Err(e) => {
            println!("✘ {e}");
            Ok(1)
        }
    }
}

async fn gateway_from(path: &Path, dev: bool) -> Result<agent_scope_gateway::Gateway, String> {
    let (cfg, base) = GatewayConfig::from_file(path).map_err(|e| e.to_string())?;
    Ok(cfg.load(&base, dev).map_err(|e| e.to_string())?.gateway)
}

/// namespaced name → (hash, definition)
async fn observed(gateway: &Path, token: Option<&str>, dev: bool) -> Result<BTreeMap<String, (String, Value)>, String> {
    let gw = gateway_from(gateway, dev).await?;
    let mut out = BTreeMap::new();
    for (up, r) in gw.upstream_tools(token).await {
        match r {
            Ok(defs) => {
                for d in defs {
                    let raw = d["name"].as_str().unwrap_or("");
                    match normalize_name(raw) {
                        Ok(n) => {
                            out.insert(format!("{up}.{n}"), (definition_hash(&d), d));
                        }
                        Err(_) => eprintln!(
                            "warning: {up}: tool `{}` has a non-normalized name and will always be rejected",
                            raw.escape_unicode()
                        ),
                    }
                }
            }
            Err(e) => eprintln!("warning: upstream `{up}` unavailable: {e}"),
        }
    }
    Ok(out)
}

pub async fn catalog_pull(gateway: &Path, lock_out: &Path, catalog_out: &Path, token: Option<&str>, dev: bool) -> Result<i32, String> {
    let tools = observed(gateway, token, dev).await?;
    let mut lock = Lock::new();
    let mut section = serde_json::Map::new();
    for (name, (hash, def)) in &tools {
        lock.pin("tool", name, hash);
        section
            .insert(name.clone(), json!({"scopes": [], "sensitivity": "read", "description": def["description"].as_str().unwrap_or("")}));
    }
    write(lock_out, &lock.to_json_string())?;
    let skeleton = json!({"version": 1, "tool": section});
    let yaml = serde_norway::to_string(&skeleton).map_err(|e| e.to_string())?;
    write(catalog_out, &format!("# Generated by `agent-scope catalog pull`. Tools without scopes are denied.\n# Add scopes and sensitivity, then merge into catalog.yaml.\n{yaml}"))?;
    println!("pinned {} tool(s) → {}\nskeleton → {}", tools.len(), lock_out.display(), catalog_out.display());
    Ok(0)
}

pub async fn catalog_diff(gateway: &Path, lock: &Path, token: Option<&str>, dev: bool) -> Result<i32, String> {
    let l = Lock::from_json_str(&read(lock)?)?;
    let tools = observed(gateway, token, dev).await?;
    let pinned = l.pins.get("tool").cloned().unwrap_or_default();
    let mut changes = 0;
    for (name, (hash, _)) in &tools {
        match pinned.get(name) {
            None => {
                println!("+ {name} (new, denied until accepted)");
                changes += 1;
            }
            Some(h) if h != hash => {
                println!("~ {name} (definition changed, denied until accepted)");
                changes += 1;
            }
            _ => {}
        }
    }
    for name in pinned.keys().filter(|n| !tools.contains_key(*n)) {
        println!("- {name} (no longer offered)");
        changes += 1;
    }
    println!("{changes} change(s)");
    Ok(if changes > 0 { 1 } else { 0 })
}

pub async fn catalog_accept(gateway: &Path, lock: &Path, only: &[String], token: Option<&str>, dev: bool) -> Result<i32, String> {
    let mut l = if lock.exists() { Lock::from_json_str(&read(lock)?)? } else { Lock::new() };
    let tools = observed(gateway, token, dev).await?;
    let mut n = 0;
    for (name, (hash, _)) in &tools {
        if only.is_empty() || only.contains(name) {
            l.pin("tool", name, hash);
            n += 1;
        }
    }
    write(lock, &l.to_json_string())?;
    println!("accepted {n} definition(s) into {}", lock.display());
    Ok(0)
}

pub fn dev_keygen() -> Result<i32, String> {
    let sts = Sts::new(StsConfig { issuer: "x".into(), token_ttl_s: 1, clients: HashMap::new() }, None)?;
    print!("{}", sts.pem());
    Ok(0)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StsFile {
    issuer: String,
    key_file: String,
    #[serde(default = "ttl")]
    token_ttl_s: i64,
    #[serde(default)]
    clients: HashMap<String, ClientDef>,
    /// Optional policy whose `may_delegate_to` edges the STS enforces.
    #[serde(default)]
    policy: Option<String>,
}

fn ttl() -> i64 {
    300
}

fn sts_from(config: &Path) -> Result<Sts, String> {
    let f: StsFile = serde_norway::from_str(&read(config)?).map_err(|e| format!("{}: {e}", config.display()))?;
    let base = config.parent().unwrap_or(Path::new("."));
    let key_path = base.join(&f.key_file);
    let pem = if key_path.exists() { Some(read(&key_path)?) } else { None };
    let mut sts = Sts::new(StsConfig { issuer: f.issuer, token_ttl_s: f.token_ttl_s, clients: f.clients }, pem.as_deref())?;
    if pem.is_none() {
        write(&key_path, sts.pem())?;
        eprintln!("created signing key {}", key_path.display());
    }
    if let Some(p) = f.policy {
        let policy = agent_scope_core::Policy::from_yaml_str(&read(&base.join(p))?)?;
        sts = sts.with_delegation_check(Arc::new(move |from: &str, to: &str| {
            policy.agents.get(from).is_some_and(|a| a.delegation.may_delegate_to.iter().any(|t| t == to))
        }));
    }
    Ok(sts)
}

pub async fn dev_sts(config: &Path, port: u16) -> Result<i32, String> {
    let sts = Arc::new(sts_from(config)?);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| e.to_string())?;
    eprintln!("\x1b[41;97m DEV \x1b[0m agent-scope dev STS on port {port}, issuer {}", sts.issuer());
    axum::serve(listener, sts.router()).await.map_err(|e| e.to_string())?;
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
pub fn dev_token(
    config: &Path,
    subject: &str,
    agent: &str,
    roles: &[String],
    attrs: &str,
    audience: &str,
    scopes: &[String],
    ttl: i64,
) -> Result<i32, String> {
    let sts = sts_from(config)?;
    let roles: Vec<&str> = roles.iter().map(String::as_str).collect();
    let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
    println!("{}", sts.user_token(subject, agent, &roles, json_arg(attrs)?, audience, &scopes, ttl)?);
    Ok(0)
}
