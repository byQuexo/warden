//! Reqwest backend for the SDK transport, remembering the session id.
//!
//! `rmcp` keeps the session id inside the worker. Tests and `post_raw` need the same
//! id the handshake just received, so this wrapper records it and otherwise delegates,
//! including the SDK's response-size limits.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures::stream::BoxStream;
use http::{HeaderName, HeaderValue};
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_client::{SseError, StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse};
use sse_stream::Sse;

#[derive(Clone)]
pub(crate) struct RecordingHttp {
    inner: reqwest::Client,
    session: Arc<Mutex<Option<String>>>,
}

impl RecordingHttp {
    pub(crate) fn new(inner: reqwest::Client, session: Arc<Mutex<Option<String>>>) -> Self {
        Self { inner, session }
    }

    fn remember(&self, id: &Option<String>) {
        if let Some(id) = id {
            if let Ok(mut slot) = self.session.lock() {
                *slot = Some(id.clone());
            }
        }
    }

    fn remember_response(&self, response: &StreamableHttpPostResponse) {
        match response {
            StreamableHttpPostResponse::Json(_, id) | StreamableHttpPostResponse::Sse(_, id) => self.remember(id),
            StreamableHttpPostResponse::Accepted => {}
            _ => {}
        }
    }
}

impl StreamableHttpClient for RecordingHttp {
    type Error = reqwest::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let response = self.inner.post_message(uri, message, session_id, auth_header, custom_headers).await?;
        self.remember_response(&response);
        Ok(response)
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let response = self
            .inner
            .post_message_with_max_sse_event_size(uri, message, session_id, auth_header, custom_headers, max_sse_event_size)
            .await?;
        self.remember_response(&response);
        Ok(response)
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.inner.delete_session(uri, session_id, auth_header, custom_headers).await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.inner.get_stream(uri, session_id, last_event_id, auth_header, custom_headers).await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        self.inner.get_stream_with_max_sse_event_size(uri, session_id, last_event_id, auth_header, custom_headers, max_sse_event_size).await
    }
}
