//! The SDK client against a tiny Streamable HTTP server.
//!
//! Covers the handshake this gateway depends on: the client offers the newest
//! revision that still has `initialize`, advertises no sampling/roots/elicitation,
//! and a server request that shares a response with the tool result is refused
//! before `call` returns.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use serde_json::{json, Value};
use warden_mcp::McpClient;

#[derive(Default)]
struct Log {
    messages: Vec<Value>,
    authorizations: Vec<Option<String>>,
}

async fn handle(State(log): State<Arc<Mutex<Log>>>, headers: HeaderMap, body: Bytes) -> Response {
    let msg: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string);
    if let Ok(mut log) = log.lock() {
        log.messages.push(msg.clone());
        log.authorizations.push(authorization);
    }
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    // Notifications and replies to server requests are acknowledged, not answered.
    if msg.get("method").is_none() || msg.get("id").is_none() {
        return StatusCode::ACCEPTED.into_response();
    }
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": true}},
            "serverInfo": {"name": "tiny", "version": "0"}
        }),
        "tools/list" => {
            let cursor = msg.pointer("/params/cursor").and_then(Value::as_str);
            if cursor == Some("p2") {
                json!({"tools": [tool("second")]})
            } else {
                json!({"tools": [tool("first")], "nextCursor": "p2"})
            }
        }
        "tools/call" => {
            let result = json!({
                "content": [{"type": "text", "text": "ok"}],
                "structuredContent": {"ok": true}
            });
            let request = json!({
                "jsonrpc": "2.0",
                "id": "srv-1",
                "method": "sampling/createMessage",
                "params": {"messages": [], "maxTokens": 1}
            });
            let progress = json!({
                "jsonrpc": "2.0",
                "method": "notifications/progress",
                "params": {"progressToken": "t", "progress": 1}
            });
            let done = json!({"jsonrpc": "2.0", "id": id, "result": result});
            let body = format!("data: {request}\n\ndata: {progress}\n\ndata: {done}\n\n");
            return Response::builder()
                .header("content-type", "text/event-stream")
                .body(body.into())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
        _ => {
            return (StatusCode::OK, json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "nope"}}).to_string())
                .into_response();
        }
    };
    let mut response = Response::builder()
        .header("content-type", "application/json")
        .body(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string().into())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    if method == "initialize" {
        response.headers_mut().insert("mcp-session-id", "sess-1".parse().unwrap());
    }
    response
}

fn tool(name: &str) -> Value {
    json!({
        "name": name,
        "description": format!("{name} tool"),
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
        "outputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": true, "unknownHint": true},
        "x-extra": 1
    })
}

async fn serve() -> (String, Arc<Mutex<Log>>) {
    let log = Arc::new(Mutex::new(Log::default()));
    let app = Router::new().route("/mcp", post(handle)).with_state(log.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), log)
}

#[tokio::test]
async fn handshake_lists_calls_and_blocks_sampling() {
    let (url, log) = serve().await;
    let client = McpClient::with_timeout(url, std::time::Duration::from_secs(5));

    let listed = client.list_all(Some("secret"), "tools/list", "tools").await.unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0]["name"], "first");
    assert_eq!(listed[0]["description"], "first tool");
    assert_eq!(listed[0]["inputSchema"]["type"], "object");
    assert_eq!(listed[0]["outputSchema"]["type"], "object");
    assert_eq!(listed[0]["annotations"]["readOnlyHint"], true);
    assert_eq!(listed[1]["name"], "second");
    assert!(client.session_id(Some("secret")).await.as_deref() == Some("sess-1"));

    let outcome = client.call(Some("secret"), "tools/call", json!({"name": "first", "arguments": {}})).await.unwrap();
    assert_eq!(outcome.result.unwrap()["structuredContent"]["ok"], true);
    assert_eq!(outcome.blocked, vec!["sampling/createMessage".to_string()]);
    assert!(outcome.notifications.iter().any(|n| n["method"] == "notifications/progress"), "{:?}", outcome.notifications);

    let log = log.lock().unwrap();
    let init = log.messages.iter().find(|m| m["method"] == "initialize").unwrap();
    assert_eq!(init["params"]["protocolVersion"], "2025-11-25");
    assert_eq!(init["params"]["clientInfo"]["name"], "warden");
    let caps = &init["params"]["capabilities"];
    assert!(caps.get("sampling").is_none(), "{caps}");
    assert!(caps.get("roots").is_none(), "{caps}");
    assert!(caps.get("elicitation").is_none(), "{caps}");
    assert!(log.authorizations.iter().any(|a| a.as_deref() == Some("Bearer secret")));
    let refusal = log.messages.iter().find(|m| m.get("error").is_some()).unwrap();
    assert_eq!(refusal["id"], "srv-1");
    assert_eq!(refusal["error"]["code"], -32601);
    assert_eq!(refusal["error"]["message"], "blocked by warden gateway");
}
