//! `mock-mcp --profile crm --port 9002`: a deterministic MCP server for demos and compose setups.

use clap::Parser;

#[derive(Parser)]
#[command(about = "Deterministic mock MCP server (Streamable HTTP, POST /mcp)")]
struct Args {
    /// hr | crm | docs | ticket | evil
    #[arg(long)]
    profile: agent_scope_testkit::Profile,
    #[arg(long, default_value_t = 9000)]
    port: u16,
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let a = Args::parse();
    let listener = tokio::net::TcpListener::bind((a.host.as_str(), a.port)).await?;
    println!("mock-mcp ({:?}) listening on http://{}/mcp", a.profile, listener.local_addr()?);
    axum::serve(listener, agent_scope_testkit::router(a.profile)).await
}
