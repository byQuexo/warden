//! # warden-mcp
//!
//! MCP client used by the warden gateway, built on [`rmcp`](https://docs.rs/rmcp) 3.9
//! (the official Rust SDK, <https://github.com/modelcontextprotocol/rust-sdk>).
//!
//! The SDK owns the Streamable HTTP and stdio transports: initialize, session ids,
//! `MCP-Protocol-Version`, SSE responses, pagination cursors and JSON-RPC errors.
//! Warden still decides what a session is allowed to do. In particular the client
//! advertises no sampling, elicitation or roots capability, and answers those server
//! requests with an error instead of the SDK's defaults (empty roots, a user-looking
//! elicitation decline).
//!
//! What stays custom, on purpose:
//!
//! * The gateway's own HTTP server. It authenticates, parses with strict JSON limits
//!   and applies policy before any SDK server handler would see the call.
//! * JSON-RPC builders shared with the A2A proxy, including Warden's `-32001` forbid
//!   code. `-32002` is kept as the upstream-failure code even though the MCP spec uses
//!   that number for "resource not found".
//! * A small SSE body parser for callers that already buffered a response (tests, A2A).
//! * `post_raw`, so tests can send bytes the SDK would refuse to construct (duplicate
//!   keys) and read the HTTP status.
//!
//! Protocol revisions this gateway is prepared to *answer* stop at `2025-06-18`.
//! `rmcp`'s latest revision (`2026-07-28`) has no `initialize` handshake; the client
//! offers [`rmcp::model::ProtocolVersion::LATEST_WITH_INITIALIZE`] (`2025-11-25`) and
//! accepts whatever the server negotiates down to.
#![forbid(unsafe_code)]

mod block;
pub mod client;
mod http;
pub mod jsonrpc;
mod order;
pub mod protocol;
pub mod sse;
pub mod stdio;

pub use client::{ClientError, McpClient, Outcome, RawResponse};
pub use protocol::{gateway_initialize_result, initialize_version_header_error, negotiate_protocol_version, session_version_header_error};
pub use stdio::StdioSpec;

/// Protocol revisions the gateway answers, newest first.
///
/// This is [`rmcp::model::ProtocolVersion::known_up_to`] `2025-06-18`, not the SDK's
/// latest. `2025-11-25` still has `initialize` but this server has not adopted that
/// revision. `2026-07-28` removed the handshake (`has_initialize() == false`).
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Newest revision the gateway will name in an `initialize` result.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

/// Server→client request methods a gateway must not fulfill.
pub const SERVER_TO_CLIENT_METHODS: &[&str] = &["sampling/createMessage", "elicitation/create", "roots/list"];
