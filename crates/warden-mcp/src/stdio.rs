//! How to start a stdio MCP server.
//!
//! The process itself is spawned by [`rmcp::transport::TokioChildProcess`]. This module
//! only records the command line the gateway was configured with.

/// How to start a stdio MCP server.
#[derive(Clone, Debug)]
pub struct StdioSpec {
    pub command: String,
    pub args: Vec<String>,
    /// Extra environment for the child process (e.g. an API token for that server).
    /// The child also inherits the gateway's environment; the gateway config layer
    /// is what applies the allow-list before building this spec.
    pub env: Vec<(String, String)>,
}
