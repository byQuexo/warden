//! # warden-mcp
//!
//! Just enough of the Model Context Protocol (JSON-RPC 2.0 over Streamable HTTP) for a
//! policy-enforcing gateway: message helpers, an SSE parser and an upstream client that
//! handles sessions, pagination and blocks server→client requests (sampling, elicitation).
#![forbid(unsafe_code)]

pub mod client;
pub mod jsonrpc;
pub mod sse;
pub mod stdio;

pub use client::{ClientError, McpClient, Outcome};
pub use stdio::StdioSpec;

/// Protocol revisions the gateway speaks, newest first.
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// Server→client request methods that a gateway must not relay by default.
pub const SERVER_TO_CLIENT_METHODS: &[&str] = &["sampling/createMessage", "elicitation/create", "roots/list"];
