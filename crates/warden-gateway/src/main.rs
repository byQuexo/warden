use std::path::PathBuf;

use clap::Parser;
use warden_gateway::config::GatewayConfig;

#[derive(Parser)]
#[command(name = "warden-gateway", version, about = "Policy-enforcing MCP gateway for AI agents")]
struct Args {
    /// Path to gateway.yaml
    #[arg(long, short)]
    config: PathBuf,
    /// Allow insecure development settings (plain-HTTP issuers, auto-approve, unsigned audit).
    #[arg(long)]
    dev: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let args = Args::parse();
    if let Err(e) = run(args).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    if args.dev {
        eprintln!("\x1b[41;97m DEV MODE \x1b[0m insecure settings are allowed; never run this in production");
    }
    let (cfg, base) = GatewayConfig::from_file(&args.config)?;
    let loaded = cfg.load(&base, args.dev)?;
    let listener = tokio::net::TcpListener::bind(&loaded.listen).await?;
    let admin = match &loaded.admin_listen {
        Some(a) => Some(tokio::net::TcpListener::bind(a).await?),
        None => None,
    };
    if let Some(every) = loaded.reload {
        loaded.gateway.spawn_reload(loaded.files.clone(), every);
    }
    tracing::info!(
        listen = %loaded.listen,
        admin = ?loaded.admin_listen,
        policy_version = %loaded.gateway.engine().version(),
        "warden gateway ready"
    );
    loaded.gateway.serve(listener, admin).await?;
    Ok(())
}
