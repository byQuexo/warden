//! Minimal `text/event-stream` parser (only `data:` lines matter for MCP).

use serde_json::Value;

/// Parse a complete SSE body into the JSON payloads of its events.
pub fn parse(body: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let mut data = String::new();
    for line in body.lines().chain(std::iter::once("")) {
        if line.is_empty() {
            if !data.is_empty() {
                if let Ok(v) = serde_json::from_str(&data) {
                    out.push(v);
                }
                data.clear();
            }
        } else if let Some(d) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(d.strip_prefix(' ').unwrap_or(d));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_events() {
        let body = "event: message\ndata: {\"a\":1}\n\nid: 2\ndata: {\"b\":\ndata: 2}\n\n";
        let v = super::parse(body);
        assert_eq!(v.len(), 2);
        assert_eq!(v[1]["b"], 2);
    }
}
