//! `mock-mcp --profile crm --port 9002`: a deterministic MCP server for demos and compose setups.
//! `mock-mcp --approver lead@acme --port 9100`: an approval webhook that approves everything.

use axum::routing::post;
use axum::{Json, Router};
use clap::Parser;
use serde_json::{json, Value};

#[derive(Parser)]
#[command(about = "Deterministic mock MCP server (Streamable HTTP, POST /mcp) or approval webhook (POST /approvals)")]
struct Args {
    /// hr | crm | docs | ticket | evil
    #[arg(long, required_unless_present = "approver")]
    profile: Option<warden_testkit::Profile>,
    /// Run an approval webhook that approves every request as this approver.
    #[arg(long)]
    approver: Option<String>,
    #[arg(long, default_value_t = 9000)]
    port: u16,
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let a = Args::parse();
    let listener = tokio::net::TcpListener::bind((a.host.as_str(), a.port)).await?;
    let addr = listener.local_addr()?;
    let router = match (a.profile, a.approver) {
        (Some(p), _) => {
            println!("mock-mcp ({p:?}) listening on http://{addr}/mcp");
            warden_testkit::router(p)
        }
        (None, Some(who)) => {
            println!("mock approver ({who}) listening on http://{addr}/approvals");
            Router::new().route(
                "/approvals",
                post(move |Json(req): Json<Value>| {
                    let who = who.clone();
                    async move {
                        println!("approval requested: {} {} by {}", req["name"], req["args"], req["subject"]);
                        Json(json!({"decision": "approve", "approver": who}))
                    }
                }),
            )
        }
        (None, None) => unreachable!("clap enforces one of --profile/--approver"),
    };
    axum::serve(listener, router).await
}
