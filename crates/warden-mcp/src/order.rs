//! Hold back the rest of a stream until a server→client message has been handled.
//!
//! `rmcp` spawns the client handler and keeps reading. A `sampling/createMessage`
//! request and the tool result often arrive in one SSE body (or as two stdio lines
//! already buffered). Without this gate the result can wake `call` before the handler
//! has recorded the block, and the audit event is lost.
//!
//! The serve loop polls this `receive` in the same `select` as the outbound sink, and
//! it drops `receive` when it takes the sink branch. Held messages therefore live on
//! the struct, not in the future. Requests are released once our reply is sent.
//! Notifications are released when the handler drops [`NoteDone`].
//!
//! Ordering is best effort, never a reason to stall. `rmcp` does not hand every
//! notification to the handler (it can consume a cancellation itself), so cancellations
//! are not counted. As a backstop, if
//! nothing is released for [`GRACE`], the gate opens anyway.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::model::{JsonRpcMessage, RequestId, ServerNotification};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::RoleClient;
use tokio::sync::Notify;

/// How long held messages may wait for a handler before the gate gives up on ordering.
const GRACE: Duration = Duration::from_secs(2);

pub(crate) struct OrderGate {
    pending: Mutex<HashSet<RequestId>>,
    notes: AtomicUsize,
    wake: Notify,
}

impl OrderGate {
    pub(crate) fn new() -> Self {
        Self { pending: Mutex::new(HashSet::new()), notes: AtomicUsize::new(0), wake: Notify::new() }
    }

    /// Pairs with [`OrderGate::begin_notification`]. Dropping it releases the next message.
    pub(crate) fn note_done(self: &Arc<Self>) -> NoteDone {
        NoteDone(Some(Arc::clone(self)))
    }

    fn begin_notification(&self) {
        self.notes.fetch_add(1, Ordering::SeqCst);
    }

    fn end_note(&self) {
        // Saturating: a release without a matching begin must not wrap the counter.
        // (A compare-exchange loop: `fetch_update` is deprecated on new toolchains and its
        // replacement is newer than the MSRV.)
        let mut current = self.notes.load(Ordering::SeqCst);
        while current > 0 {
            match self.notes.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        self.wake.notify_one();
    }

    fn begin_request(&self, id: RequestId) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id);
        }
    }

    fn end_request(&self, id: &RequestId) {
        let removed = self.pending.lock().map(|mut pending| pending.remove(id)).unwrap_or(false);
        if removed {
            self.wake.notify_one();
        }
    }

    fn idle(&self) -> bool {
        self.notes.load(Ordering::SeqCst) == 0 && self.pending.lock().map(|pending| pending.is_empty()).unwrap_or(true)
    }

    /// Forget everything in flight. Used when a handler never reported back.
    fn open(&self) {
        tracing::warn!("mcp order gate: no handler progress within {GRACE:?}; releasing held messages");
        self.notes.store(0, Ordering::SeqCst);
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }
}

/// Whether this notification is paired with a [`NoteDone`] from the handler.
///
/// `notifications/cancelled` is not: under the modern lifecycle `rmcp` drops a
/// cancellation for an unknown subscription without calling the handler. Other
/// notifications reach it; this client never registers a subscription, so the serve
/// loop has nowhere else to route one that carries a subscription id.
fn reaches_handler(notification: &ServerNotification) -> bool {
    !matches!(notification, ServerNotification::CancelledNotification(_))
}

/// Decrements the in-flight notification count on drop.
pub(crate) struct NoteDone(Option<Arc<OrderGate>>);

impl Drop for NoteDone {
    fn drop(&mut self) {
        if let Some(gate) = self.0.take() {
            gate.end_note();
        }
    }
}

pub(crate) struct OrderTransport<T> {
    inner: T,
    gate: Arc<OrderGate>,
    held: VecDeque<RxJsonRpcMessage<RoleClient>>,
    inner_closed: bool,
    grace: Duration,
}

impl<T> OrderTransport<T> {
    pub(crate) fn new(inner: T, gate: Arc<OrderGate>) -> Self {
        Self { inner, gate, held: VecDeque::new(), inner_closed: false, grace: GRACE }
    }

    fn deliver(&mut self, msg: RxJsonRpcMessage<RoleClient>) -> RxJsonRpcMessage<RoleClient> {
        match &msg {
            JsonRpcMessage::Request(request) => self.gate.begin_request(request.id.clone()),
            JsonRpcMessage::Notification(n) if reaches_handler(&n.notification) => self.gate.begin_notification(),
            JsonRpcMessage::Notification(_) | JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_) => {}
        }
        msg
    }
}

impl<T> Transport<RoleClient> for OrderTransport<T>
where
    T: Transport<RoleClient> + Send,
{
    type Error = T::Error;

    fn send(&mut self, item: TxJsonRpcMessage<RoleClient>) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let answered = match &item {
            JsonRpcMessage::Response(response) => Some(response.id.clone()),
            JsonRpcMessage::Error(error) => error.id.clone(),
            JsonRpcMessage::Request(_) | JsonRpcMessage::Notification(_) => None,
        };
        let gate = Arc::clone(&self.gate);
        let sending = self.inner.send(item);
        async move {
            let result = sending.await;
            if let Some(id) = answered.as_ref() {
                gate.end_request(id);
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
        loop {
            if self.gate.idle() {
                if let Some(msg) = self.held.pop_front() {
                    return Some(self.deliver(msg));
                }
                if self.inner_closed {
                    return None;
                }
            } else if self.inner_closed && self.held.is_empty() {
                return None;
            }

            let gate = Arc::clone(&self.gate);
            if self.inner_closed {
                if tokio::time::timeout(self.grace, gate.wake.notified()).await.is_err() {
                    gate.open();
                }
                continue;
            }

            let waiting = !self.held.is_empty();
            tokio::select! {
                biased;
                _ = gate.wake.notified(), if waiting => {}
                _ = tokio::time::sleep(self.grace), if waiting => gate.open(),
                msg = self.inner.receive() => {
                    match msg {
                        None => self.inner_closed = true,
                        Some(msg) if self.gate.idle() && self.held.is_empty() => {
                            return Some(self.deliver(msg));
                        }
                        Some(msg) => self.held.push_back(msg),
                    }
                }
            }
        }
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use serde_json::{json, Value};

    /// Yields scripted messages, then stays open.
    struct Script(VecDeque<RxJsonRpcMessage<RoleClient>>);

    impl Transport<RoleClient> for Script {
        type Error = std::io::Error;

        fn send(&mut self, _item: TxJsonRpcMessage<RoleClient>) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            std::future::ready(Ok(()))
        }

        async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
            match self.0.pop_front() {
                Some(m) => Some(m),
                None => std::future::pending().await,
            }
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn msg(v: Value) -> RxJsonRpcMessage<RoleClient> {
        serde_json::from_value(v).expect("valid server message")
    }

    fn progress() -> RxJsonRpcMessage<RoleClient> {
        msg(json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "t", "progress": 1}}))
    }

    fn result() -> RxJsonRpcMessage<RoleClient> {
        msg(json!({"jsonrpc": "2.0", "id": 1, "result": {}}))
    }

    fn transport(messages: Vec<RxJsonRpcMessage<RoleClient>>, grace: Duration) -> (OrderTransport<Script>, Arc<OrderGate>) {
        let gate = Arc::new(OrderGate::new());
        let mut t = OrderTransport::new(Script(messages.into()), Arc::clone(&gate));
        t.grace = grace;
        (t, gate)
    }

    fn is_response(m: &RxJsonRpcMessage<RoleClient>) -> bool {
        matches!(m, JsonRpcMessage::Response(_))
    }

    #[tokio::test]
    async fn result_waits_for_the_notification_handler() {
        let (mut t, gate) = transport(vec![progress(), result()], Duration::from_secs(30));
        assert!(matches!(t.receive().await, Some(JsonRpcMessage::Notification(_))));
        let held = tokio::time::timeout(Duration::from_millis(100), t.receive()).await;
        assert!(held.is_err(), "result must wait for the handler");
        drop(gate.note_done());
        let next = tokio::time::timeout(Duration::from_secs(5), t.receive()).await.expect("released").expect("message");
        assert!(is_response(&next));
    }

    #[tokio::test]
    async fn cancellations_are_not_held() {
        let cancelled = msg(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}}));
        let (mut t, _gate) = transport(vec![cancelled, result()], Duration::from_secs(30));
        assert!(matches!(t.receive().await, Some(JsonRpcMessage::Notification(_))));
        let next = tokio::time::timeout(Duration::from_secs(5), t.receive()).await.expect("not held").expect("message");
        assert!(is_response(&next));
    }

    #[tokio::test]
    async fn a_handler_that_never_reports_back_does_not_wedge_the_stream() {
        let (mut t, _gate) = transport(vec![progress(), result()], Duration::from_millis(50));
        assert!(matches!(t.receive().await, Some(JsonRpcMessage::Notification(_))));
        let next = tokio::time::timeout(Duration::from_secs(5), t.receive()).await.expect("gate opened").expect("message");
        assert!(is_response(&next));
    }

    #[test]
    fn release_without_begin_does_not_wrap() {
        let gate = Arc::new(OrderGate::new());
        drop(gate.note_done());
        assert!(gate.idle());
        gate.begin_notification();
        assert!(!gate.idle());
    }
}
