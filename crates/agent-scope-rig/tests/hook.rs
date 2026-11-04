#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The hook runs inside rig's own hook stack (via rig-agent's test harness).

use std::sync::Arc;

use agent_scope_audit::{AuditSink, MemorySink};
use agent_scope_core::{AttrValue, Engine, Principal, Subject};
use agent_scope_gateway::{ApprovalOutcome, ApprovalRequest, Approver};
use agent_scope_rig::{tool_call, visible_tools, ScopeHook, Verdict};
use rig_agent::agent::{AgentHook, DispatchAction, DispatchEvent};
use rig_agent::test_utils::HookTestHarness;
use rig_core::effect::{EffectId, EffectKind};

const POLICY: &str = include_str!("../../../examples/acme/policy.yaml");
const CATALOG: &str = include_str!("../../../examples/acme/catalog.yaml");

fn engine() -> Arc<Engine> {
    Arc::new(Engine::builder().policy_yaml(POLICY).catalog_yaml(CATALOG).build().unwrap())
}

fn sven() -> Principal {
    Principal::new(Subject::user("sven").with_roles(["sales-rep"]).with_attr("tenants", AttrValue::List(vec!["dach".into()])), "acme-bot")
}

struct Fixed(ApprovalOutcome);

#[async_trait::async_trait]
impl Approver for Fixed {
    async fn request(&self, _req: &ApprovalRequest) -> ApprovalOutcome {
        self.0.clone()
    }
}

async fn dispatch(hook: &ScopeHook, kind: &EffectKind) -> DispatchAction {
    let harness = HookTestHarness::new();
    let event = DispatchEvent { id: EffectId::from_raw(1), kind, turn: 0, call_id: None, context: None };
    hook.on_dispatch(harness.context(), event).await
}

#[tokio::test]
async fn allowed_calls_proceed_with_the_checked_arguments() {
    let hook = ScopeHook::new(engine(), sven()).with_prefix("crm.");
    let action = dispatch(&hook, &tool_call("list_deals", r#"{ "tenant" : "dach" }"#)).await;
    match action {
        DispatchAction::Patch(EffectKind::ToolCall { name, args }) => {
            assert_eq!(name, "list_deals");
            assert_eq!(args, r#"{"tenant":"dach"}"#, "canonical, re-serialized arguments");
        }
        other => panic!("expected patch, got {other:?}"),
    }
}

#[tokio::test]
async fn denied_calls_are_skipped_with_a_generic_message() {
    let sink = MemorySink::new();
    let hook = ScopeHook::new(engine(), sven()).with_prefix("crm.").with_audit(sink.clone(), b"k".to_vec());
    for args in [r#"{"tenant":"enterprise"}"#, r#"{"tenant":"dach","tenant":"enterprise"}"#, "not json"] {
        match dispatch(&hook, &tool_call("list_deals", args)).await {
            DispatchAction::Deny(report) => assert_eq!(report.message, "This action is not permitted."),
            other => panic!("expected deny for {args}, got {other:?}"),
        }
    }
    let decisions = sink.events_of("decision");
    assert_eq!(decisions.len(), 1, "unparsable arguments never reach the engine");
    assert_eq!(decisions[0]["rule"], "tenant-pinning");
    assert_eq!(decisions[0]["adapter"], "rig");
}

#[tokio::test]
async fn completions_pass_through() {
    let hook = ScopeHook::new(engine(), sven());
    let kind = EffectKind::Completion { request: Arc::new(rig_core::completion::CompletionRequest::new("hi")), stream: false };
    assert!(matches!(dispatch(&hook, &kind).await, DispatchAction::Proceed));
}

#[tokio::test]
async fn approvals_and_audit_failure() {
    let big = r#"{"tenant":"dach","deal_id":"d-1","amount":80000}"#;
    let none = ScopeHook::new(engine(), sven()).with_prefix("crm.");
    assert_eq!(none.decide("update_deal", big).await, Verdict::Skip("This action was not approved.".into()));

    let lead = none.clone().with_approver(Arc::new(Fixed(ApprovalOutcome::Approved { approver: "lead@acme".into() })));
    assert!(matches!(lead.decide("update_deal", big).await, Verdict::Run(_)));

    let selfie = none.clone().with_approver(Arc::new(Fixed(ApprovalOutcome::Approved { approver: "sven".into() })));
    assert!(matches!(selfie.decide("update_deal", big).await, Verdict::Skip(_)));

    let sink = MemorySink::new();
    sink.set_failing(true);
    let failing = ScopeHook::new(engine(), sven()).with_prefix("crm.").with_audit(sink as Arc<dyn AuditSink>, vec![]);
    assert!(matches!(failing.decide("list_deals", r#"{"tenant":"dach"}"#).await, Verdict::Skip(_)));
}

#[test]
fn offers_only_visible_tools() {
    let names = ["list_deals", "update_deal", "export_deals", "query"];
    assert_eq!(visible_tools(&engine(), &sven(), "crm.", names), vec!["list_deals", "update_deal", "query"]);
}
