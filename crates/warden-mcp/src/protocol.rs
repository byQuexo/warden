//! Version negotiation and the gateway's `initialize` result, using `rmcp` types.

use rmcp::model::{CallToolResult, ContentBlock, Implementation, InitializeResult, ProtocolVersion, ServerCapabilities};
use rmcp::select_protocol_version;
use serde_json::{json, Value};

use crate::{LATEST_PROTOCOL_VERSION, PROTOCOL_VERSIONS};

/// Revisions this process will agree to during `initialize`.
pub fn supported_protocol_versions() -> &'static [ProtocolVersion] {
    ProtocolVersion::known_up_to(&ProtocolVersion::V_2025_06_18)
}

/// Echo `requested` when it is one of [`supported_protocol_versions`]; otherwise the
/// newest revision this server speaks.
///
/// [`select_protocol_version`] is the SDK's "first shared version" helper. The
/// initialize spec is stricter than a client preference list: a server that does not
/// share the client's version answers with one it does speak, it does not fail the
/// handshake. That fallback is `2025-06-18`.
pub fn negotiate_protocol_version(requested: &str) -> &'static str {
    let requested_version =
        serde_json::from_value::<ProtocolVersion>(Value::String(requested.to_string())).unwrap_or(ProtocolVersion::V_2025_06_18);
    let chosen = select_protocol_version(&[requested_version], supported_protocol_versions()).unwrap_or(ProtocolVersion::V_2025_06_18);
    PROTOCOL_VERSIONS.iter().copied().find(|v| *v == chosen.as_str()).unwrap_or(LATEST_PROTOCOL_VERSION)
}

/// Header check for `initialize`. A missing header is normal: the version is not
/// negotiated yet. A header that disagrees with `params.protocolVersion`, or names a
/// revision this server does not speak, is rejected.
pub fn initialize_version_header_error(header: Option<&str>, body_version: &str) -> Option<&'static str> {
    let header = blank_to_none(header)?;
    if header != body_version {
        return Some("MCP-Protocol-Version does not match protocolVersion");
    }
    if !PROTOCOL_VERSIONS.contains(&header) {
        return Some("unsupported MCP-Protocol-Version");
    }
    None
}

/// Header check after the handshake. A missing header is tolerated so a
/// `2025-03-26` client still works; the session's negotiated revision is assumed.
/// A present header must be that revision.
pub fn session_version_header_error(header: Option<&str>, negotiated: &str) -> Option<&'static str> {
    let header = blank_to_none(header)?;
    if !PROTOCOL_VERSIONS.contains(&header) {
        return Some("unsupported MCP-Protocol-Version");
    }
    if header != negotiated {
        return Some("MCP-Protocol-Version does not match the negotiated session");
    }
    None
}

fn blank_to_none(header: Option<&str>) -> Option<&str> {
    header.map(str::trim).filter(|s| !s.is_empty())
}

/// `initialize` result object for the gateway. `server_version` is the gateway crate
/// version, not this crate's (they match today; the caller owns the string).
pub fn gateway_initialize_result(protocol: &str, server_version: &str) -> Value {
    let protocol_version =
        serde_json::from_value::<ProtocolVersion>(Value::String(protocol.to_string())).unwrap_or(ProtocolVersion::V_2025_06_18);
    let capabilities = ServerCapabilities::builder()
        .enable_completions()
        .enable_prompts()
        .enable_resources()
        .enable_tools()
        .enable_tool_list_changed()
        .build();
    let result = InitializeResult::new(capabilities)
        .with_protocol_version(protocol_version)
        .with_server_info(Implementation::new("warden-gateway", server_version))
        .with_instructions("Tools are filtered for the signed-in user and agent. Every call is checked again.");
    serde_json::to_value(result).unwrap_or_else(|_| {
        json!({
            "protocolVersion": protocol,
            "capabilities": {"tools": {"listChanged": true}, "resources": {}, "prompts": {}, "completions": {}},
            "serverInfo": {"name": "warden-gateway", "version": server_version}
        })
    })
}

/// Tool result the model can read, flagged as an error.
///
/// `resultType` is omitted. The SDK sets it for `2026-07-28`, and this gateway does
/// not speak that revision.
pub fn tool_error(text: &str) -> Value {
    let mut result = CallToolResult::error(vec![ContentBlock::text(text)]);
    result.result_type = None;
    serde_json::to_value(result).unwrap_or_else(|_| json!({"content": [{"type": "text", "text": text}], "isError": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_versions_match_the_sdk_ceiling() {
        let from_sdk: Vec<&str> = supported_protocol_versions().iter().map(|v| v.as_str()).collect();
        let mut advertised = PROTOCOL_VERSIONS.to_vec();
        advertised.sort_unstable();
        let mut from_sdk_sorted = from_sdk.clone();
        from_sdk_sorted.sort_unstable();
        assert_eq!(advertised, from_sdk_sorted);
        assert_eq!(LATEST_PROTOCOL_VERSION, ProtocolVersion::V_2025_06_18.as_str());
        assert!(ProtocolVersion::V_2025_11_25.has_initialize());
        assert!(!ProtocolVersion::LATEST.has_initialize());
        assert!(!from_sdk.contains(&ProtocolVersion::LATEST.as_str()));
    }

    #[test]
    fn negotiation_echoes_known_versions_and_falls_back() {
        assert_eq!(negotiate_protocol_version("2024-11-05"), "2024-11-05");
        assert_eq!(negotiate_protocol_version("2025-03-26"), "2025-03-26");
        assert_eq!(negotiate_protocol_version("2025-06-18"), "2025-06-18");
        assert_eq!(negotiate_protocol_version("2025-11-25"), LATEST_PROTOCOL_VERSION);
        assert_eq!(negotiate_protocol_version("2026-07-28"), LATEST_PROTOCOL_VERSION);
        assert_eq!(negotiate_protocol_version("nope"), LATEST_PROTOCOL_VERSION);
    }

    #[test]
    fn header_rules() {
        assert!(initialize_version_header_error(None, "2026-07-28").is_none());
        assert!(initialize_version_header_error(Some("2025-06-18"), "2025-06-18").is_none());
        assert!(initialize_version_header_error(Some("2026-07-28"), "2026-07-28").is_some());
        assert!(initialize_version_header_error(Some("2025-06-18"), "2025-03-26").is_some());
        assert!(session_version_header_error(None, "2025-06-18").is_none());
        assert!(session_version_header_error(Some("2025-06-18"), "2025-06-18").is_none());
        assert!(session_version_header_error(Some("2025-03-26"), "2025-06-18").is_some());
        assert!(session_version_header_error(Some("2099-01-01"), "2025-06-18").is_some());
    }

    #[test]
    fn initialize_result_round_trips_through_the_sdk() {
        let v = gateway_initialize_result("2025-06-18", "0.1.0");
        let parsed: InitializeResult = serde_json::from_value(v.clone()).expect("sdk accepts the result");
        assert_eq!(parsed.protocol_version.as_str(), "2025-06-18");
        assert_eq!(parsed.capabilities.tools.as_ref().and_then(|t| t.list_changed), Some(true));
        assert!(parsed.capabilities.resources.is_some());
        assert!(parsed.capabilities.prompts.is_some());
        assert!(parsed.capabilities.completions.is_some());
        assert!(parsed.capabilities.logging.is_none());
        assert_eq!(v["serverInfo"]["name"], "warden-gateway");
        assert_eq!(v["instructions"], "Tools are filtered for the signed-in user and agent. Every call is checked again.");
    }

    #[test]
    fn tool_error_has_no_result_type() {
        let v = tool_error("no");
        assert_eq!(v["isError"], true);
        assert_eq!(v["content"][0]["type"], "text");
        assert_eq!(v["content"][0]["text"], "no");
        assert!(v.get("resultType").is_none());
    }
}
