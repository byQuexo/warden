//! Human approval for `require_approval` decisions.
//!
//! The gateway holds the call, asks an [`Approver`], re-checks the policy afterwards and
//! forwards exactly the arguments that were approved. Approvals are never cached.

use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

/// Versioned webhook payload (`v: 1`). The approver sees the clear-text arguments; the
/// approval is bound to `args_hash`, so different arguments need a new approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub v: u32,
    pub id: String,
    pub subject: String,
    pub agent: String,
    pub act: Vec<String>,
    pub kind: String,
    pub name: String,
    pub args: Value,
    pub args_hash: String,
    pub rule: String,
    pub reason: String,
    pub policy_version: String,
    /// The rule says `approve_by: subject`: the requesting subject confirms its own action, and
    /// only the subject may answer. Absent (false) for ordinary approvals by others.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub confirmation: bool,
}

/// May `approver` answer a hold for `subject`? Ordinary approvals refuse self-approval; a
/// confirmation (`approve_by: subject`) must come from the subject itself.
pub fn approver_allowed(confirmation: bool, subject: &str, approver: &str) -> Result<(), &'static str> {
    match (confirmation, approver == subject) {
        (false, true) => Err("self-approval is not allowed"),
        (true, false) => Err("a confirmation must come from the requesting subject"),
        _ => Ok(()),
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalOutcome {
    Approved { approver: String },
    Denied { approver: String, reason: String },
    Failed(String),
}

#[async_trait]
pub trait Approver: Send + Sync {
    async fn request(&self, req: &ApprovalRequest) -> ApprovalOutcome;
}

/// Denies every approval request (safe default when no approver is configured).
pub struct DenyAll;

#[async_trait]
impl Approver for DenyAll {
    async fn request(&self, _req: &ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Denied { approver: "deny-all".into(), reason: "no approver configured".into() }
    }
}

/// Approves everything. Only allowed with `--dev`.
pub struct AutoApprove;

#[async_trait]
impl Approver for AutoApprove {
    async fn request(&self, _req: &ApprovalRequest) -> ApprovalOutcome {
        ApprovalOutcome::Approved { approver: "auto-approve(dev)".into() }
    }
}

/// POSTs the request as JSON and expects `{"decision": "approve"|"deny", "approver": "..."}`.
/// With a secret, the body is signed: `X-Warden-Signature: sha256=<hex hmac>`.
pub struct WebhookApprover {
    url: String,
    secret: Option<Vec<u8>>,
    http: reqwest::Client,
}

impl WebhookApprover {
    pub fn new(url: impl Into<String>, secret: Option<Vec<u8>>, timeout: Duration) -> Self {
        Self { url: url.into(), secret, http: reqwest::Client::builder().timeout(timeout).build().unwrap_or_default() }
    }
}

#[derive(Deserialize)]
struct WebhookAnswer {
    decision: String,
    #[serde(default)]
    approver: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    args_hash: Option<String>,
}

#[async_trait]
impl Approver for WebhookApprover {
    async fn request(&self, req: &ApprovalRequest) -> ApprovalOutcome {
        let body = match serde_json::to_string(req) {
            Ok(b) => b,
            Err(e) => return ApprovalOutcome::Failed(e.to_string()),
        };
        let mut r = self.http.post(&self.url).header("content-type", "application/json");
        if let Some(secret) = &self.secret {
            if let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(secret) {
                mac.update(body.as_bytes());
                r = r.header("x-warden-signature", format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
            }
        }
        let resp = match r.body(body).send().await {
            Ok(x) if x.status().is_success() => x,
            Ok(x) => return ApprovalOutcome::Failed(format!("approver returned HTTP {}", x.status())),
            Err(e) => return ApprovalOutcome::Failed(e.to_string()),
        };
        let a: WebhookAnswer = match resp.json().await {
            Ok(a) => a,
            Err(e) => return ApprovalOutcome::Failed(format!("invalid approver answer: {e}")),
        };
        if a.args_hash.as_ref().is_some_and(|h| h != &req.args_hash) {
            return ApprovalOutcome::Failed("approval was given for different arguments".into());
        }
        match a.decision.as_str() {
            "approve" if !a.approver.is_empty() => ApprovalOutcome::Approved { approver: a.approver },
            "approve" => ApprovalOutcome::Failed("approval without approver identity".into()),
            "deny" => ApprovalOutcome::Denied { approver: a.approver, reason: a.reason },
            other => ApprovalOutcome::Failed(format!("unknown decision `{other}`")),
        }
    }
}
