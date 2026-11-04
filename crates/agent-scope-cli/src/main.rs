//! `agent-scope`: the command line for policy authors, operators and CI.

mod commands;
mod demo;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agent-scope", version, about = "Authorization for AI agents: lint, explain, evaluate and audit policies")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
pub struct PolicyArgs {
    #[arg(long, default_value = "policy.yaml")]
    pub policy: PathBuf,
    #[arg(long, default_value = "catalog.yaml")]
    pub catalog: PathBuf,
    /// Optional catalog.lock with pinned upstream definitions.
    #[arg(long)]
    pub lock: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a minimal policy, catalog and identity config to start from.
    Init {
        #[arg(default_value = ".")]
        dir: PathBuf,
    },
    /// Check policy + catalog (+ identity) for errors and risky patterns.
    Lint {
        #[command(flatten)]
        files: PolicyArgs,
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Treat warnings as errors.
        #[arg(long)]
        strict: bool,
    },
    /// Explain one decision step by step.
    Explain {
        #[command(flatten)]
        files: PolicyArgs,
        /// Principal as JSON, or @file.json
        #[arg(long)]
        principal: String,
        /// `kind:name`, e.g. `tool:crm.update_deal` or `resource:docs://hr/a.md`
        #[arg(long)]
        action: String,
        /// Arguments as JSON (parsed strictly).
        #[arg(long, default_value = "{}")]
        args: String,
        /// Context as JSON, e.g. '{"kill_switch":"writes","values":{"hour_utc":10}}'
        #[arg(long)]
        context: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Run scenario suites, generated attacks and mutation tests; enforce CI gates.
    Eval {
        #[command(flatten)]
        files: PolicyArgs,
        /// Scenario YAML files.
        #[arg(long = "suite")]
        suites: Vec<PathBuf>,
        /// Add attack cases generated from the policy.
        #[arg(long)]
        generate: bool,
        /// Remove each rule and require at least one case to fail.
        #[arg(long)]
        mutate: bool,
        /// Require every rule to fire and hold back at least once.
        #[arg(long)]
        coverage: bool,
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        write_baseline: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        json: Option<PathBuf>,
        /// Exit with status 1 if any gate fails.
        #[arg(long)]
        gate: bool,
    },
    /// Audit log tools.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Pin upstream tool definitions (rug-pull protection).
    Catalog {
        #[command(subcommand)]
        cmd: CatalogCmd,
    },
    /// Development helpers: local STS/IdP and tokens.
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
    /// Run the whole stack in-process and walk through the security story.
    Demo,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify hash chains and checkpoint signatures.
    Verify {
        dir: PathBuf,
        /// Base64 Ed25519 public key of the checkpoint signer.
        #[arg(long)]
        pubkey: Option<String>,
        /// Maximum events after the last checkpoint.
        #[arg(long, default_value_t = 1000)]
        max_unanchored: u64,
    },
    /// Generate an Ed25519 checkpoint key pair.
    Keygen,
}

#[derive(Subcommand)]
enum CatalogCmd {
    /// List upstream tools and write a lock file plus a catalog skeleton.
    Pull {
        #[arg(long)]
        gateway: PathBuf,
        #[arg(long, default_value = "catalog.lock")]
        lock_out: PathBuf,
        #[arg(long, default_value = "catalog.skeleton.yaml")]
        catalog_out: PathBuf,
        /// Bearer token used for token-exchange upstreams.
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        dev: bool,
    },
    /// Show tools whose definition differs from the lock.
    Diff {
        #[arg(long)]
        gateway: PathBuf,
        #[arg(long, default_value = "catalog.lock")]
        lock: PathBuf,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        dev: bool,
    },
    /// Accept current definitions into the lock (all, or `--tool` ones).
    Accept {
        #[arg(long)]
        gateway: PathBuf,
        #[arg(long, default_value = "catalog.lock")]
        lock: PathBuf,
        #[arg(long = "tool")]
        tools: Vec<String>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        dev: bool,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// Generate an ES256 signing key (PKCS#8 PEM) for the dev STS.
    Keygen,
    /// Run a local STS / dev IdP (OIDC discovery, JWKS, client credentials, token exchange).
    Sts {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_t = 9400)]
        port: u16,
    },
    /// Mint a user access token with the dev STS key.
    Token {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        subject: String,
        #[arg(long)]
        agent: String,
        #[arg(long, value_delimiter = ',')]
        roles: Vec<String>,
        #[arg(long, default_value = "{}")]
        attrs: String,
        #[arg(long)]
        audience: String,
        #[arg(long, value_delimiter = ',')]
        scopes: Vec<String>,
        #[arg(long, default_value_t = 3600)]
        ttl: i64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli.cmd).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    std::process::exit(code);
}

async fn run(cmd: Cmd) -> Result<i32, String> {
    match cmd {
        Cmd::Init { dir } => commands::init(&dir),
        Cmd::Lint { files, identity, strict } => commands::lint(&files, identity.as_deref(), strict),
        Cmd::Explain { files, principal, action, args, context, json } => commands::explain(&files, &principal, &action, &args, context.as_deref(), json),
        Cmd::Eval { files, suites, generate, mutate, coverage, baseline, write_baseline, report, json, gate } => {
            commands::eval(commands::EvalOpts { files, suites, generate, mutate, coverage, baseline, write_baseline, report, json, gate })
        }
        Cmd::Audit { cmd: AuditCmd::Verify { dir, pubkey, max_unanchored } } => commands::audit_verify(&dir, pubkey.as_deref(), max_unanchored),
        Cmd::Audit { cmd: AuditCmd::Keygen } => {
            let (sk, pk) = agent_scope_audit::generate_signing_key();
            println!("AUDIT_SIGNING_KEY={sk}\nAUDIT_PUBLIC_KEY={pk}");
            Ok(0)
        }
        Cmd::Catalog { cmd } => match cmd {
            CatalogCmd::Pull { gateway, lock_out, catalog_out, token, dev } => commands::catalog_pull(&gateway, &lock_out, &catalog_out, token.as_deref(), dev).await,
            CatalogCmd::Diff { gateway, lock, token, dev } => commands::catalog_diff(&gateway, &lock, token.as_deref(), dev).await,
            CatalogCmd::Accept { gateway, lock, tools, token, dev } => commands::catalog_accept(&gateway, &lock, &tools, token.as_deref(), dev).await,
        },
        Cmd::Dev { cmd } => match cmd {
            DevCmd::Keygen => commands::dev_keygen(),
            DevCmd::Sts { config, port } => commands::dev_sts(&config, port).await,
            DevCmd::Token { config, subject, agent, roles, attrs, audience, scopes, ttl } => {
                commands::dev_token(&config, &subject, &agent, &roles, &attrs, &audience, &scopes, ttl)
            }
        },
        Cmd::Demo => demo::run().await,
    }
}
