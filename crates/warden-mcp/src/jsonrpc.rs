//! JSON-RPC 2.0 message helpers.
//!
//! Standard codes come from [`rmcp::model::ErrorCode`]. The two application codes are
//! Warden's: the A2A proxy uses the same builders, and those messages are not MCP.

use rmcp::model::ErrorCode;
use serde_json::{json, Value};

pub const PARSE_ERROR: i64 = ErrorCode::PARSE_ERROR.0 as i64;
pub const INVALID_REQUEST: i64 = ErrorCode::INVALID_REQUEST.0 as i64;
pub const METHOD_NOT_FOUND: i64 = ErrorCode::METHOD_NOT_FOUND.0 as i64;
pub const INVALID_PARAMS: i64 = ErrorCode::INVALID_PARAMS.0 as i64;
pub const INTERNAL_ERROR: i64 = ErrorCode::INTERNAL_ERROR.0 as i64;

/// Application error: the action was denied by policy. Not an MCP standard code.
pub const FORBIDDEN: i64 = -32001;

/// Application error: an upstream failed.
///
/// The MCP spec uses `-32002` for "resource not found" ([`ErrorCode::RESOURCE_NOT_FOUND`]).
/// This process already emits `-32002` for upstream failures. The number is unchanged
/// so existing clients keep matching it; new code should read the message, not treat
/// `-32002` as MCP's resource-not-found.
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
    crate::protocol::tool_error(text)
}

/// Classification of an incoming message.
///
/// The gateway runs strict JSON parsing before this, so duplicate keys
/// and depth limits are rejected first. Deserializing straight into an `rmcp` request
/// enum would turn an unknown method into a parse failure instead of "method not found",
/// and it would accept the last of a duplicate key. This classifier stays.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_codes_match_the_sdk() {
        assert_eq!(PARSE_ERROR, -32700);
        assert_eq!(INVALID_REQUEST, i64::from(ErrorCode::INVALID_REQUEST.0));
        assert_eq!(METHOD_NOT_FOUND, i64::from(ErrorCode::METHOD_NOT_FOUND.0));
        assert_eq!(INVALID_PARAMS, i64::from(ErrorCode::INVALID_PARAMS.0));
        assert_eq!(INTERNAL_ERROR, i64::from(ErrorCode::INTERNAL_ERROR.0));
        assert_eq!(UPSTREAM_ERROR, i64::from(ErrorCode::RESOURCE_NOT_FOUND.0));
        assert_ne!(FORBIDDEN, i64::from(ErrorCode::RESOURCE_NOT_FOUND.0));
    }
}
