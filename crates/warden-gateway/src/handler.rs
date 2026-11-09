//! The MCP endpoint: authentication, sessions, list filtering and call enforcement.
// Early-return `Result<_, Response>` keeps handlers readable; responses are built once per request.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};
use warden_audit::args_hmac;
use warden_core::json::{parse_strict, Limits as JsonLimits};
use warden_core::lock::definition_hash;
use warden_core::normalize::{collision_key, normalize_name, normalize_uri};
use warden_core::{Action, ActionKind, Decision, Effect, Principal};
use warden_identity::{enrich, now_unix};
use warden_mcp::jsonrpc::{self, Message};
use warden_mcp::{
    gateway_initialize_result, initialize_version_header_error, negotiate_protocol_version, session_version_header_error,
    LATEST_PROTOCOL_VERSION,
};

use crate::approval::{approver_allowed, ApprovalOutcome, ApprovalRequest};
use crate::gateway::{Gateway, SessionRecord, Upstream};

fn json_rpc(status: StatusCode, v: Value) -> Response {
    (status, [("content-type", "application/json")], v.to_string()).into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ").map(str::trim)
}

fn unauthorized(gw: &Gateway, msg: &str) -> Response {
    let base = gw.public_url.trim_end_matches('/');
    let origin = base.rsplit_once("/mcp").map(|(o, _)| o).unwrap_or(base);
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("www-authenticate", format!("Bearer resource_metadata=\"{origin}/.well-known/oauth-protected-resource\""))
        .header("content-type", "application/json")
        .body(Body::from(jsonrpc::error(Value::Null, jsonrpc::FORBIDDEN, msg).to_string()))
        .unwrap_or_default()
}

/// Authenticate the request and resolve attributes.
async fn authenticate(gw: &Gateway, headers: &HeaderMap) -> Result<(Principal, String), Response> {
    let Some(token) = bearer(headers) else {
        return Err(unauthorized(gw, "missing bearer token"));
    };
    let p = match gw.verifier.verify(token, now_unix()).await {
        Ok(p) => p,
        Err(e) => {
            gw.record("token_rejected", json!({"code": e.code(), "detail": e.to_string()}));
            return Err(unauthorized(gw, "invalid token"));
        }
    };
    let p = match &gw.resolver {
        None => p,
        Some(r) => match enrich(r.as_ref(), p.clone()).await {
            Ok(p) => p,
            Err(e) => {
                let mut f = Gateway::principal_fields(&p);
                f.insert("detail".into(), json!(e));
                gw.record("attrs_unavailable", Value::Object(f));
                return Err(json_rpc(StatusCode::FORBIDDEN, jsonrpc::error(Value::Null, jsonrpc::FORBIDDEN, "attributes unavailable")));
            }
        },
    };
    Ok((p, token.to_string()))
}

fn new_session_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Check that the session exists and belongs to this principal.
fn check_session(gw: &Gateway, headers: &HeaderMap, p: &Principal) -> Result<String, Response> {
    let Some(sid) = headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) else {
        return Err(json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(Value::Null, jsonrpc::INVALID_REQUEST, "missing Mcp-Session-Id")));
    };
    let record = gw.sessions.lock().ok().and_then(|s| s.get(sid).cloned());
    match record {
        None => Err(json_rpc(StatusCode::NOT_FOUND, jsonrpc::error(Value::Null, jsonrpc::INVALID_REQUEST, "unknown session"))),
        Some(o) if o.owner != p.identity_key() => {
            let mut f = Gateway::principal_fields(p);
            f.insert("session".into(), json!(sid));
            gw.record("session_mismatch", Value::Object(f));
            Err(json_rpc(
                StatusCode::FORBIDDEN,
                jsonrpc::error(Value::Null, jsonrpc::FORBIDDEN, "session belongs to a different principal"),
            ))
        }
        Some(o) => {
            if let Some(why) = session_version_header_error(protocol_header(headers), &o.protocol) {
                return Err(json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(Value::Null, jsonrpc::INVALID_REQUEST, why)));
            }
            Ok(sid.to_string())
        }
    }
}

fn protocol_header(headers: &HeaderMap) -> Option<&str> {
    headers.get("mcp-protocol-version").and_then(|v| v.to_str().ok())
}

pub async fn post(State(gw): State<Gateway>, headers: HeaderMap, body: Bytes) -> Response {
    let (p, token) = match authenticate(&gw, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Ok(text) = std::str::from_utf8(&body) else {
        return json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(Value::Null, jsonrpc::PARSE_ERROR, "body is not UTF-8"));
    };
    let limits = JsonLimits { max_bytes: gw.limits.request_bytes, max_depth: gw.limits.json_depth };
    let msg = match parse_strict(text, limits) {
        Ok(v) => v,
        Err(e) => {
            let mut f = Gateway::principal_fields(&p);
            f.insert("detail".into(), json!(e.to_string()));
            gw.record("request_rejected", Value::Object(f));
            return json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(Value::Null, jsonrpc::PARSE_ERROR, &format!("rejected: {e}")));
        }
    };
    if msg.is_array() {
        return json_rpc(
            StatusCode::BAD_REQUEST,
            jsonrpc::error(Value::Null, jsonrpc::INVALID_REQUEST, "JSON-RPC batches are not supported"),
        );
    }
    let (id, method, params) = match jsonrpc::classify(&msg) {
        Message::Invalid(why) => return json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(Value::Null, jsonrpc::INVALID_REQUEST, why)),
        Message::Notification { .. } | Message::Response => {
            return Response::builder().status(StatusCode::ACCEPTED).body(Body::empty()).unwrap_or_default();
        }
        Message::Request { id, method, params } => (id.clone(), method.to_string(), params.clone()),
    };

    if method == "initialize" {
        let sid = new_session_id();
        let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(LATEST_PROTOCOL_VERSION);
        if let Some(why) = initialize_version_header_error(protocol_header(&headers), requested) {
            return json_rpc(StatusCode::BAD_REQUEST, jsonrpc::error(id, jsonrpc::INVALID_REQUEST, why));
        }
        let version = negotiate_protocol_version(requested);
        if let Ok(mut s) = gw.sessions.lock() {
            s.insert(sid.clone(), SessionRecord { owner: p.identity_key(), protocol: version.to_string() });
        }
        let result = gateway_initialize_result(version, env!("CARGO_PKG_VERSION"));
        return Response::builder()
            .header("content-type", "application/json")
            .header("mcp-session-id", sid)
            .body(Body::from(jsonrpc::ok(id, result).to_string()))
            .unwrap_or_default();
    }
    if let Err(r) = check_session(&gw, &headers, &p) {
        return r;
    }

    let wants_sse = headers.get("accept").and_then(|v| v.to_str().ok()).is_some_and(|a| a.contains("text/event-stream"));
    let progress_token = params.pointer("/_meta/progressToken").cloned();

    let reply = match method.as_str() {
        "ping" => jsonrpc::ok(id, json!({})),
        "tools/list" => jsonrpc::ok(id, list_tools(&gw, &p, &token).await),
        "tools/call" => {
            if wants_sse && progress_token.is_some() {
                return call_tool_streaming(gw, p, token, id, params, progress_token.unwrap_or(Value::Null));
            }
            tools_call(&gw, &p, &token, id, &params, None).await
        }
        "resources/list" => jsonrpc::ok(id, list_resources(&gw, &p, &token).await),
        "resources/templates/list" => jsonrpc::ok(id, json!({"resourceTemplates": []})),
        "resources/read" => read_resource(&gw, &p, &token, id, &params).await,
        "prompts/list" => jsonrpc::ok(id, list_prompts(&gw, &p, &token).await),
        "prompts/get" => get_prompt(&gw, &p, &token, id, &params).await,
        "completion/complete" => complete(&gw, &p, &token, id, &params).await,
        _ => jsonrpc::error(id, jsonrpc::METHOD_NOT_FOUND, "method not found"),
    };
    json_rpc(StatusCode::OK, reply)
}

/// `GET /mcp`: server-initiated messages (only `notifications/tools/list_changed`).
pub async fn get(State(gw): State<Gateway>, headers: HeaderMap) -> Response {
    let (p, _) = match authenticate(&gw, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(r) = check_session(&gw, &headers, &p) {
        return r;
    }
    let stream = BroadcastStream::new(gw.subscribe_list_changed()).map(|_| {
        Ok::<_, Infallible>(Event::default().data(jsonrpc::notification("notifications/tools/list_changed", json!({})).to_string()))
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

pub async fn delete(State(gw): State<Gateway>, headers: HeaderMap) -> Response {
    let (p, _) = match authenticate(&gw, &headers).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match check_session(&gw, &headers, &p) {
        Ok(sid) => {
            if let Ok(mut s) = gw.sessions.lock() {
                s.remove(&sid);
            }
            StatusCode::OK.into_response()
        }
        Err(r) => r,
    }
}

async fn credential(gw: &Gateway, up: &Upstream, token: &str) -> Result<Option<String>, String> {
    up.auth.credential(&gw.http, &gw.token_cache, token, now_unix()).await
}

/// Record an upstream failure and feed the circuit breaker.
fn upstream_error(gw: &Gateway, upstream: &str, detail: &str) {
    gw.record("upstream_error", json!({"upstream": upstream, "detail": detail}));
    gw.upstream_failed(upstream);
}

/// Annotations shown to the client come from the catalog, never from the upstream.
fn catalog_annotations(gw: &Gateway, name: &str) -> Value {
    let engine = gw.engine();
    match engine.catalog().resolve(&ActionKind::Tool, name) {
        Some(r) => json!({
            "readOnlyHint": r.sensitivity == warden_core::Sensitivity::Read,
            "destructiveHint": r.tags.contains("destructive"),
        }),
        None => json!({}),
    }
}

async fn list_tools(gw: &Gateway, p: &Principal, token: &str) -> Value {
    let engine = gw.engine();
    let ctx = gw.context();
    let mut out: Vec<Value> = Vec::new();
    let mut keys: HashMap<String, usize> = HashMap::new();
    let mut collided: Vec<String> = Vec::new();
    for (name, up) in &gw.upstreams {
        if !gw.upstream_available(name) {
            continue;
        }
        let cred = match credential(gw, up, token).await {
            Ok(c) => c,
            Err(e) => {
                upstream_error(gw, name, &e);
                continue;
            }
        };
        let defs = match gw.definitions(up, cred.as_deref(), true).await {
            Ok(d) => d,
            Err(e) => {
                upstream_error(gw, name, &e);
                continue;
            }
        };
        for def in defs {
            let raw = def.get("name").and_then(Value::as_str).unwrap_or("");
            let full = match normalize_name(raw).and_then(|l| normalize_name(&format!("{name}.{l}"))) {
                Ok(f) => f,
                Err(_) => {
                    gw.record(
                        "tool_rejected",
                        json!({"upstream": name, "name": raw, "reason": "name is not a normalized ASCII identifier"}),
                    );
                    continue;
                }
            };
            let hash = definition_hash(&def);
            if let Some(lock) = engine.lock() {
                match lock.pinned("tool", &full) {
                    Some(None) => {
                        gw.record("tool_unpinned", json!({"tool": full, "hash": hash}));
                    }
                    Some(Some(h)) if h != hash => {
                        gw.record("tool_changed", json!({"tool": full, "pinned": h, "observed": hash}));
                    }
                    _ => {}
                }
            }
            let key = collision_key(&full);
            if keys.contains_key(&key) {
                collided.push(key);
                continue;
            }
            let action = Action::tool(&full, Value::Null).with_definition_hash(&hash);
            if engine.visible(p, &action, &ctx) {
                let mut d = def.clone();
                d["name"] = json!(full);
                d["annotations"] = catalog_annotations(gw, &full);
                keys.insert(key, out.len());
                out.push(d);
            }
        }
    }
    if !collided.is_empty() {
        for k in &collided {
            gw.record("tool_rejected", json!({"name": k, "reason": "name collision after normalization"}));
        }
        out.retain(|d| !collided.contains(&collision_key(d["name"].as_str().unwrap_or(""))));
    }
    json!({"tools": out})
}

fn split_namespaced<'a>(gw: &'a Gateway, name: &str) -> Option<(&'a Upstream, String)> {
    let (up, local) = name.split_once('.')?;
    Some((gw.upstreams.get(up)?, local.to_string()))
}

fn deny_tool(d: &Decision) -> Value {
    jsonrpc::tool_error(&d.model_message)
}

/// Enforce and forward a `tools/call`. With `progress`, approval waiting emits progress notifications.
async fn tools_call(
    gw: &Gateway,
    p: &Principal,
    token: &str,
    id: Value,
    params: &Value,
    progress: Option<(Value, mpsc::Sender<Value>)>,
) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "missing tool name");
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    if !args.is_object() {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "arguments must be an object");
    }
    let engine = gw.engine();
    let ctx = gw.context();

    // Resolve the upstream definition for pinning (fresh enough to catch rug pulls).
    let routed = split_namespaced(gw, name);
    let mut raw_name = None;
    let mut hash = None;
    if let Some((up, local)) = &routed {
        let cred = credential(gw, up, token).await.ok().flatten();
        if let Ok(defs) = gw.definitions(up, cred.as_deref(), false).await {
            if let Some(def) = defs
                .iter()
                .find(|d| d.get("name").and_then(Value::as_str).and_then(|n| normalize_name(n).ok()).as_deref() == Some(local.as_str()))
            {
                raw_name = def.get("name").and_then(Value::as_str).map(str::to_string);
                hash = Some(definition_hash(def));
            }
        }
    }
    let mut action = Action::tool(name, args.clone());
    if let Some(h) = &hash {
        action = action.with_definition_hash(h);
    }
    let d = gw.audit_decision(p, &action, engine.check(p, &action, &ctx));
    let (Some((up, _)), Some(raw)) = (routed, raw_name) else {
        if d.effect == Effect::Deny {
            return jsonrpc::ok(id, deny_tool(&d));
        }
        return jsonrpc::ok(id, jsonrpc::tool_error("Unknown tool."));
    };
    match d.effect {
        Effect::Deny => jsonrpc::ok(id, deny_tool(&d)),
        Effect::Allow => forward_tool(gw, p, token, up, id, &raw, args).await,
        Effect::RequireApproval => match approve(gw, p, &action, &d, progress).await {
            Ok(()) => forward_tool(gw, p, token, up, id, &raw, args).await,
            Err(denied) => jsonrpc::ok(id, jsonrpc::tool_error(&denied)),
        },
    }
}

async fn forward_tool(gw: &Gateway, p: &Principal, token: &str, up: &Upstream, id: Value, raw: &str, args: Value) -> Value {
    if !gw.upstream_available(&up.name) {
        return jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream unavailable (circuit open)");
    }
    let cred = match credential(gw, up, token).await {
        Ok(c) => c,
        Err(e) => {
            upstream_error(gw, &up.name, &e);
            return jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream authentication failed");
        }
    };
    match up.client.call(cred.as_deref(), "tools/call", json!({"name": raw, "arguments": args})).await {
        Ok(o) => {
            gw.upstream_ok(&up.name);
            for m in &o.blocked {
                let mut f = Gateway::principal_fields(p);
                f.insert("upstream".into(), json!(up.name));
                f.insert("method".into(), json!(m));
                gw.record("server_request_blocked", Value::Object(f));
            }
            match o.result {
                Ok(r) if r.to_string().len() > gw.limits.result_bytes => {
                    gw.record("upstream_error", json!({"upstream": up.name, "detail": "result exceeds size limit"}));
                    jsonrpc::ok(id, jsonrpc::tool_error("The tool result was too large and has been withheld."))
                }
                Ok(r) => jsonrpc::ok(id, r),
                Err((code, msg)) => jsonrpc::error(id, code, &msg),
            }
        }
        Err(e) => {
            upstream_error(gw, &up.name, &e.to_string());
            jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream unavailable")
        }
    }
}

/// Ask the approver; on success, re-check before forwarding. `Err` carries the model message.
async fn approve(
    gw: &Gateway,
    p: &Principal,
    action: &Action,
    d: &Decision,
    progress: Option<(Value, mpsc::Sender<Value>)>,
) -> Result<(), String> {
    let denied = "This action was not approved.".to_string();
    let args_hash = args_hmac(&gw.hmac_key, &action.args);
    let confirmation = gw.engine().approved_by_subject(&d.rule);
    let req = ApprovalRequest {
        v: 1,
        id: hex::encode(rand::random::<[u8; 12]>()),
        subject: p.subject.id.clone(),
        agent: p.agent.clone(),
        act: p.act.clone(),
        kind: action.kind.to_string(),
        name: action.name.clone(),
        args: action.args.clone(),
        args_hash: args_hash.clone(),
        rule: d.rule.clone(),
        reason: d.reason.clone(),
        policy_version: d.policy_version.clone(),
        confirmation,
    };
    let mut base = Gateway::principal_fields(p);
    base.insert("approval_id".into(), json!(req.id));
    base.insert("rule".into(), json!(d.rule));
    if confirmation {
        base.insert("confirmation".into(), json!(true));
    }
    base.insert("args_hmac".into(), json!(args_hash));
    if !gw.record("approval_requested", Value::Object(base.clone())) {
        return Err(denied);
    }

    let wait = gw.approver.request(&req);
    let outcome = match progress {
        None => tokio::time::timeout(gw.approval_timeout, wait).await.ok(),
        Some((token, tx)) => {
            tokio::pin!(wait);
            let deadline = tokio::time::sleep(gw.approval_timeout);
            tokio::pin!(deadline);
            let mut tick = tokio::time::interval(gw.progress_interval);
            let mut n = 0u64;
            loop {
                tokio::select! {
                    o = &mut wait => break Some(o),
                    _ = &mut deadline => break None,
                    _ = tick.tick() => {
                        n += 1;
                        let note = jsonrpc::notification("notifications/progress", json!({
                            "progressToken": token, "progress": n, "message": "waiting for human approval"
                        }));
                        let _ = tx.send(note).await;
                    }
                }
            }
        }
    };

    let fail = |event: &str, detail: String| {
        let mut f = base.clone();
        f.insert("detail".into(), json!(detail));
        gw.record(event, Value::Object(f));
    };
    match outcome {
        None => {
            fail("approval_timeout", "no answer in time".into());
            Err(denied)
        }
        Some(ApprovalOutcome::Failed(e)) => {
            fail("approval_timeout", e);
            Err(denied)
        }
        Some(ApprovalOutcome::Denied { approver, reason }) => {
            fail("approval_denied", format!("{approver}: {reason}"));
            Err(denied)
        }
        Some(ApprovalOutcome::Approved { approver }) if approver_allowed(confirmation, &p.subject.id, &approver).is_err() => {
            let why = approver_allowed(confirmation, &p.subject.id, &approver).err().unwrap_or_default();
            fail("approval_denied", why.into());
            Err(denied)
        }
        Some(ApprovalOutcome::Approved { approver }) => {
            let mut f = base.clone();
            f.insert("approver".into(), json!(approver));
            if !gw.record("approval_granted", Value::Object(f)) {
                return Err(denied);
            }
            // Re-check: the token may have expired and the policy may have changed meanwhile.
            if p.expires_at.is_some_and(|exp| exp < now_unix()) {
                fail("approval_denied", "token expired while waiting for approval".into());
                return Err(denied);
            }
            let engine = gw.engine();
            if engine.version() != d.policy_version {
                fail("approval_denied", "policy changed while waiting for approval".into());
                return Err(denied);
            }
            let again = engine.check(p, action, &gw.context());
            if again.effect == Effect::Deny {
                fail("approval_denied", format!("re-check denied: {}", again.rule));
                return Err(denied);
            }
            Ok(())
        }
    }
}

fn call_tool_streaming(gw: Gateway, p: Principal, token: String, id: Value, params: Value, progress_token: Value) -> Response {
    let (tx, rx) = mpsc::channel::<Value>(16);
    tokio::spawn(async move {
        let final_msg = tools_call(&gw, &p, &token, id, &params, Some((progress_token, tx.clone()))).await;
        let _ = tx.send(final_msg).await;
    });
    let stream = ReceiverStream::new(rx).map(|v| Ok::<_, Infallible>(Event::default().data(v.to_string())));
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))).into_response()
}

fn route_resource<'a>(gw: &'a Gateway, uri: &str) -> Option<&'a Upstream> {
    gw.upstreams.values().find(|u| u.resource_prefixes.iter().any(|p| uri.starts_with(p.as_str())))
}

async fn list_resources(gw: &Gateway, p: &Principal, token: &str) -> Value {
    let engine = gw.engine();
    let ctx = gw.context();
    let mut out = Vec::new();
    for (name, up) in gw.upstreams.iter().filter(|(n, u)| !u.resource_prefixes.is_empty() && gw.upstream_available(n)) {
        let cred = match credential(gw, up, token).await {
            Ok(c) => c,
            Err(e) => {
                upstream_error(gw, name, &e);
                continue;
            }
        };
        match up.client.list_all(cred.as_deref(), "resources/list", "resources").await {
            Ok(items) => {
                gw.upstream_ok(name);
                for r in items {
                    let uri = r.get("uri").and_then(Value::as_str).unwrap_or("");
                    let owned = up.resource_prefixes.iter().any(|p| uri.starts_with(p.as_str()));
                    if owned && engine.visible(p, &Action::resource(uri), &ctx) {
                        out.push(r);
                    }
                }
            }
            Err(e) => upstream_error(gw, name, &e.to_string()),
        }
    }
    json!({"resources": out})
}

async fn read_resource(gw: &Gateway, p: &Principal, token: &str, id: Value, params: &Value) -> Value {
    let Some(raw) = params.get("uri").and_then(Value::as_str) else {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "missing uri");
    };
    let action = Action::resource(raw);
    let d = gw.audit_decision(p, &action, gw.engine().check(p, &action, &gw.context()));
    if d.effect != Effect::Allow {
        // Approval for resource reads is not supported over MCP; treat as deny.
        return jsonrpc::error(id, jsonrpc::FORBIDDEN, &d.model_message);
    }
    let Ok(uri) = normalize_uri(raw) else {
        return jsonrpc::error(id, jsonrpc::FORBIDDEN, "This action is not permitted.");
    };
    let Some(up) = route_resource(gw, &uri) else {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "no upstream serves this resource");
    };
    forward_generic(gw, token, up, id, "resources/read", json!({"uri": uri})).await
}

async fn list_prompts(gw: &Gateway, p: &Principal, token: &str) -> Value {
    let engine = gw.engine();
    let ctx = gw.context();
    let mut out = Vec::new();
    for (name, up) in &gw.upstreams {
        let cred = match credential(gw, up, token).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if !gw.upstream_available(name) {
            continue;
        }
        let items = match up.client.list_all(cred.as_deref(), "prompts/list", "prompts").await {
            Ok(i) => i,
            Err(e) => {
                upstream_error(gw, name, &e.to_string());
                continue;
            }
        };
        for pr in items {
            let raw = pr.get("name").and_then(Value::as_str).unwrap_or("");
            let Ok(full) = normalize_name(raw).and_then(|l| normalize_name(&format!("{name}.{l}"))) else { continue };
            let action = Action::prompt(&full, Value::Null).with_definition_hash(definition_hash(&pr));
            if engine.visible(p, &action, &ctx) {
                let mut x = pr.clone();
                x["name"] = json!(full);
                out.push(x);
            }
        }
    }
    json!({"prompts": out})
}

async fn get_prompt(gw: &Gateway, p: &Principal, token: &str, id: Value, params: &Value) -> Value {
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "missing prompt name");
    };
    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let action = Action::prompt(name, args.clone());
    let d = gw.audit_decision(p, &action, gw.engine().check(p, &action, &gw.context()));
    if d.effect != Effect::Allow {
        return jsonrpc::error(id, jsonrpc::FORBIDDEN, &d.model_message);
    }
    let Some((up, local)) = split_namespaced(gw, name) else {
        return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "unknown prompt");
    };
    forward_generic(gw, token, up, id, "prompts/get", json!({"name": local, "arguments": args})).await
}

async fn complete(gw: &Gateway, p: &Principal, token: &str, id: Value, params: &Value) -> Value {
    let r = params.get("ref").cloned().unwrap_or(Value::Null);
    let (action, up, forwarded_ref) = match r.get("type").and_then(Value::as_str) {
        Some("ref/prompt") => {
            let name = r.get("name").and_then(Value::as_str).unwrap_or("");
            let Some((up, local)) = split_namespaced(gw, name) else {
                return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "unknown prompt");
            };
            (Action::prompt(name, Value::Null), up, json!({"type": "ref/prompt", "name": local}))
        }
        Some("ref/resource") => {
            let uri = r.get("uri").and_then(Value::as_str).unwrap_or("");
            let Some(up) = normalize_uri(uri).ok().and_then(|u| route_resource(gw, &u)) else {
                return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "unknown resource");
            };
            (Action::resource(uri), up, r.clone())
        }
        _ => return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "unsupported ref"),
    };
    let d = gw.engine().visible(p, &action, &gw.context());
    if !d {
        return jsonrpc::error(id, jsonrpc::FORBIDDEN, "This action is not permitted.");
    }
    let mut fwd = params.clone();
    fwd["ref"] = forwarded_ref;
    forward_generic(gw, token, up, id, "completion/complete", fwd).await
}

async fn forward_generic(gw: &Gateway, token: &str, up: &Upstream, id: Value, method: &str, params: Value) -> Value {
    if !gw.upstream_available(&up.name) {
        return jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream unavailable (circuit open)");
    }
    let cred = match credential(gw, up, token).await {
        Ok(c) => c,
        Err(e) => {
            upstream_error(gw, &up.name, &e);
            return jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream authentication failed");
        }
    };
    match up.client.call(cred.as_deref(), method, params).await {
        Ok(o) => {
            gw.upstream_ok(&up.name);
            match o.result {
                Ok(r) if r.to_string().len() > gw.limits.result_bytes => jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "result too large"),
                Ok(r) => jsonrpc::ok(id, r),
                Err((c, m)) => jsonrpc::error(id, c, &m),
            }
        }
        Err(e) => {
            upstream_error(gw, &up.name, &e.to_string());
            jsonrpc::error(id, jsonrpc::UPSTREAM_ERROR, "upstream unavailable")
        }
    }
}

/// RFC 9728 protected resource metadata.
pub async fn protected_resource(State(gw): State<Gateway>) -> Response {
    let engine = gw.engine();
    let issuers: Vec<&str> = gw.verifier.config().issuers.iter().map(|i| i.issuer.as_str()).collect();
    axum::Json(json!({
        "resource": gw.public_url,
        "authorization_servers": issuers,
        "bearer_methods_supported": ["header"],
        "scopes_supported": engine.catalog().all_scopes(),
        "resource_name": "warden gateway",
    }))
    .into_response()
}
