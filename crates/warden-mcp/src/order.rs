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

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rmcp::model::{JsonRpcMessage, RequestId};
use rmcp::service::{RxJsonRpcMessage, TxJsonRpcMessage};
use rmcp::transport::Transport;
use rmcp::RoleClient;
use tokio::sync::Notify;

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
        let prev = self.notes.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            self.notes.store(0, Ordering::SeqCst);
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
}

impl<T> OrderTransport<T> {
    pub(crate) fn new(inner: T, gate: Arc<OrderGate>) -> Self {
        Self { inner, gate, held: VecDeque::new(), inner_closed: false }
    }

    fn deliver(&mut self, msg: RxJsonRpcMessage<RoleClient>) -> RxJsonRpcMessage<RoleClient> {
        match &msg {
            JsonRpcMessage::Request(request) => self.gate.begin_request(request.id.clone()),
            JsonRpcMessage::Notification(_) => self.gate.begin_notification(),
            JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_) => {}
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

            if self.inner_closed {
                Arc::clone(&self.gate).wake.notified().await;
                continue;
            }

            let gate = Arc::clone(&self.gate);
            let waiting = !self.held.is_empty();
            tokio::select! {
                biased;
                _ = gate.wake.notified(), if waiting => {}
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
