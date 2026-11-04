//! # warden-gateway
//!
//! An MCP gateway that sits between agents and MCP servers and enforces warden policy:
//!
//! * verifies the caller's token and binds the MCP session to that principal
//! * `tools/list`, `resources/list`, `prompts/list` show only what the principal may use
//! * every `tools/call`, `resources/read`, `prompts/get` is checked again
//! * arguments are parsed strictly and forwarded exactly as checked
//! * upstream definitions are pinned (`catalog.lock`), names normalized, annotations replaced
//! * `require_approval` holds the call until a human approves, then re-checks
//! * every decision is written to a tamper-evident audit log; audit failure = deny
#![forbid(unsafe_code)]

pub mod admin;
pub mod approval;
pub mod config;
pub mod gateway;
pub mod handler;
pub mod upstream_auth;

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tower_http::catch_panic::CatchPanicLayer;

pub use approval::{ApprovalOutcome, ApprovalRequest, Approver, AutoApprove, DenyAll, WebhookApprover};
pub use gateway::{Gateway, GatewayBuilder, GatewayError, Limits, SinkErrorMode};
pub use upstream_auth::UpstreamAuth;

impl Gateway {
    /// The public MCP router.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/mcp", post(handler::post).get(handler::get).delete(handler::delete))
            .route("/.well-known/oauth-protected-resource", get(handler::protected_resource))
            .route("/.well-known/oauth-protected-resource/mcp", get(handler::protected_resource))
            .route("/healthz", get(|| async { "ok" }))
            .layer(DefaultBodyLimit::max(self.limits.request_bytes + 1024))
            // A panic in a handler becomes a 500 (= the call does not happen), the process lives on.
            .layer(CatchPanicLayer::new())
            .with_state(self.clone())
    }

    /// Current tool definitions of every upstream (for `warden catalog pull/accept`).
    pub async fn upstream_tools(
        &self,
        subject_token: Option<&str>,
    ) -> std::collections::BTreeMap<String, Result<Vec<serde_json::Value>, String>> {
        let mut out = std::collections::BTreeMap::new();
        for (name, up) in &self.upstreams {
            let r = async {
                let cred =
                    up.auth.credential(&self.http, &self.token_cache, subject_token.unwrap_or(""), warden_identity::now_unix()).await?;
                self.definitions(up, cred.as_deref(), true).await
            }
            .await;
            out.insert(name.clone(), r);
        }
        out
    }

    pub fn admin_router(&self) -> Router {
        admin::router(self.clone())
    }

    /// Serve the MCP router (and optionally the admin router) until the process ends.
    pub async fn serve(self, listener: tokio::net::TcpListener, admin: Option<tokio::net::TcpListener>) -> std::io::Result<()> {
        if let Some(a) = admin {
            let r = self.admin_router();
            tokio::spawn(async move {
                let _ = axum::serve(a, r).await;
            });
        }
        axum::serve(listener, self.router()).await
    }

    /// Poll the policy files and swap the engine when they change. A file that fails to
    /// parse or lint is rejected and the previous policy stays active.
    pub fn spawn_reload(&self, files: (PathBuf, PathBuf, Option<PathBuf>), every: Duration) {
        let gw = self.clone();
        tokio::spawn(async move {
            let stamp = |files: &(PathBuf, PathBuf, Option<PathBuf>)| -> Vec<Option<SystemTime>> {
                [Some(&files.0), Some(&files.1), files.2.as_ref()]
                    .into_iter()
                    .map(|p| p.and_then(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok()))
                    .collect()
            };
            let mut last = stamp(&files);
            let mut tick = tokio::time::interval(every);
            loop {
                tick.tick().await;
                let now = stamp(&files);
                if now == last {
                    continue;
                }
                last = now;
                match config::load_engine(&files.0, &files.1, files.2.as_deref()) {
                    Ok(e) => {
                        let version = e.version().to_string();
                        gw.swap_engine(e);
                        gw.record("policy_reloaded", json!({"policy_version": version}));
                        tracing::info!(%version, "policy reloaded");
                    }
                    Err(err) => {
                        gw.record("policy_reload_failed", json!({"detail": err.to_string()}));
                        tracing::error!(%err, "policy reload rejected; keeping previous policy");
                    }
                }
            }
        });
    }
}
