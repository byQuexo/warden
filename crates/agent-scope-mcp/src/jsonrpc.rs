//! JSON-RPC 2.0 message helpers.

use serde_json::{json, Value};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// Application error: the action was denied by policy.
pub const FORBIDDEN: i64 = -32001;
/// Application error: an upstream failed.
pub const UPSTREAM_ERROR: i64 = -32002;

pub fn request(id: Value, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

pub fn notification(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

pub fn ok(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// A tool result the model can read, flagged as an error.
pub fn tool_error(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

/// Classification of an incoming message.
pub enum Message<'a> {
    Request { id: &'a Value, method: &'a str, params: &'a Value },
    Notification { method: &'a str },
    Response,
    Invalid(&'static str),
}

pub fn classify(v: &Value) -> Message<'_> {
    static NULL: Value = Value::Null;
    if v.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Message::Invalid("jsonrpc must be \"2.0\"");
    }
    match (v.get("method").and_then(Value::as_str), v.get("id")) {
        (Some(m), Some(id)) if id.is_string() || id.is_number() => {
            Message::Request { id, method: m, params: v.get("params").unwrap_or(&NULL) }
        }
        (Some(_), Some(_)) => Message::Invalid("id must be a string or number"),
        (Some(m), None) => Message::Notification { method: m },
        (None, Some(_)) if v.get("result").is_some() || v.get("error").is_some() => Message::Response,
        _ => Message::Invalid("not a JSON-RPC message"),
    }
}
