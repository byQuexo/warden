//! Client handler that refuses server→client requests.
//!
//! `rmcp`'s default handler returns an empty `roots/list` and *declines* elicitation,
//! which is a user decision, not a refusal. A gateway must not answer either. Sampling
//! already defaults to method-not-found; we still record it so the audit log can show
//! that an upstream asked.

use std::sync::{Arc, Mutex};

#[allow(deprecated)]
use rmcp::model::{
    CancelledNotificationParam, ClientConfig, CreateMessageRequestParams, CreateMessageResult, CustomNotification, CustomRequest,
    CustomResult, ElicitRequestParams, ElicitResult, ErrorCode, ErrorData, ListRootsResult, LoggingMessageNotificationParam,
    ProgressNotificationParam, ResourceUpdatedNotificationParam, SubscriptionsAcknowledgedNotificationParams, TaskStatusNotificationParams,
};
use rmcp::service::{NotificationContext, RequestContext, RoleClient};
use rmcp::ClientHandler;
use serde::Serialize;
use serde_json::{json, Value};

use crate::jsonrpc;
use crate::order::{NoteDone, OrderGate};

const BLOCKED: &str = "blocked by warden gateway";

#[derive(Clone)]
pub(crate) struct BlockingHandler {
    info: ClientConfig,
    blocked: Arc<Mutex<Vec<String>>>,
    notes: Arc<Mutex<Vec<Value>>>,
    gate: Arc<OrderGate>,
}

impl BlockingHandler {
    pub(crate) fn new(info: ClientConfig, gate: Arc<OrderGate>) -> Self {
        Self { info, blocked: Arc::new(Mutex::new(Vec::new())), notes: Arc::new(Mutex::new(Vec::new())), gate }
    }

    pub(crate) fn blocked_handle(&self) -> Arc<Mutex<Vec<String>>> {
        self.blocked.clone()
    }

    pub(crate) fn notes_handle(&self) -> Arc<Mutex<Vec<Value>>> {
        self.notes.clone()
    }

    fn block(&self, method: &str) -> ErrorData {
        if let Ok(mut g) = self.blocked.lock() {
            g.push(method.to_string());
        }
        ErrorData::new(ErrorCode::METHOD_NOT_FOUND, BLOCKED, None)
    }

    fn note<T: Serialize>(&self, method: &str, params: &T) {
        let params = serde_json::to_value(params).unwrap_or(Value::Null);
        self.note_value(method, params);
    }

    fn note_value(&self, method: &str, params: Value) {
        if let Ok(mut n) = self.notes.lock() {
            n.push(jsonrpc::notification(method, params));
        }
    }

    fn finish_note(&self) -> NoteDone {
        self.gate.note_done()
    }
}

#[allow(deprecated)]
impl ClientHandler for BlockingHandler {
    fn get_info(&self) -> ClientConfig {
        self.info.clone()
    }

    async fn ping(&self, _context: RequestContext<RoleClient>) -> Result<(), ErrorData> {
        Err(self.block("ping"))
    }

    async fn create_message(
        &self,
        _params: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<CreateMessageResult, ErrorData> {
        Err(self.block("sampling/createMessage"))
    }

    async fn list_roots(&self, _context: RequestContext<RoleClient>) -> Result<ListRootsResult, ErrorData> {
        Err(self.block("roots/list"))
    }

    async fn create_elicitation(
        &self,
        _request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        Err(self.block("elicitation/create"))
    }

    async fn on_custom_request(&self, request: CustomRequest, _context: RequestContext<RoleClient>) -> Result<CustomResult, ErrorData> {
        Err(self.block(&request.method))
    }

    async fn on_cancelled(&self, params: CancelledNotificationParam, _context: NotificationContext<RoleClient>) {
        // Not gated: the order transport does not hold the stream for cancellations.
        self.note("notifications/cancelled", &params);
    }

    async fn on_progress(&self, params: ProgressNotificationParam, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note("notifications/progress", &params);
    }

    async fn on_logging_message(&self, params: LoggingMessageNotificationParam, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note("notifications/message", &params);
    }

    async fn on_resource_updated(&self, params: ResourceUpdatedNotificationParam, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note("notifications/resources/updated", &params);
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note_value("notifications/resources/list_changed", json!({}));
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note_value("notifications/tools/list_changed", json!({}));
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note_value("notifications/prompts/list_changed", json!({}));
    }

    async fn on_subscriptions_acknowledged(
        &self,
        params: SubscriptionsAcknowledgedNotificationParams,
        _context: NotificationContext<RoleClient>,
    ) {
        let _done = self.finish_note();
        self.note("notifications/subscriptions/acknowledged", &params);
    }

    async fn on_task_status(&self, params: TaskStatusNotificationParams, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note("notifications/tasks", &params);
    }

    async fn on_custom_notification(&self, notification: CustomNotification, _context: NotificationContext<RoleClient>) {
        let _done = self.finish_note();
        self.note_value(&notification.method, notification.params.unwrap_or(Value::Null));
    }
}
