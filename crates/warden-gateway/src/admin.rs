//! Admin API (separate listener, bearer admin token): explain, effective rights, kill switch,
//! upstreams, audit tail. Intended for an operator console.

use std::collections::BTreeMap;

use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use warden_core::{Action, Context, Engine, KillSwitch, Principal};

use crate::gateway::Gateway;

pub fn router(gw: Gateway) -> Router {
    Router::new()
        .route("/v1/explain", post(explain))
        .route("/v1/effective", post(effective))
        .route("/v1/kill", get(get_kill).post(set_kill))
        .route("/v1/upstreams", get(upstreams))
        .route("/v1/audit/tail", get(tail))
        .route("/v1/policy", get(policy))
        .layer(middleware::from_fn_with_state(gw.clone(), auth))
        .with_state(gw)
}

async fn auth(State(gw): State<Gateway>, req: Request, next: Next) -> Response {
    let Some(expected) = gw.admin_token.as_deref() else {
        return (StatusCode::NOT_FOUND, "admin API disabled").into_response();
    };
    let given = req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let ok = given.is_some_and(|g| g.len() == expected.len() && g.bytes().zip(expected.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0);
    if !ok {
        return (StatusCode::UNAUTHORIZED, "admin token required").into_response();
    }
    next.run(req).await
}

#[derive(Deserialize)]
struct ExplainReq {
    principal: Principal,
    action: Action,
    #[serde(default)]
    context: Option<Context>,
}

/// Admin questions are about policy, so actions without a definition hash are evaluated
/// as if the upstream still serves the pinned definition.
fn assume_pinned(engine: &Engine, mut a: Action) -> Action {
    if a.definition_hash.is_none() {
        if let Some(Some(h)) = engine.lock().and_then(|l| l.pinned(a.kind.as_str(), &a.name)) {
            a.definition_hash = Some(h.to_string());
        }
    }
    a
}

async fn explain(State(gw): State<Gateway>, Json(r): Json<ExplainReq>) -> Response {
    let ctx = r.context.unwrap_or_else(|| gw.context());
    let engine = gw.engine();
    let d = engine.explain(&r.principal, &assume_pinned(&engine, r.action), &ctx);
    Json(json!({"decision": d, "rendered": d.render()})).into_response()
}

#[derive(Deserialize)]
struct EffectiveReq {
    principal: Principal,
}

async fn effective(State(gw): State<Gateway>, Json(r): Json<EffectiveReq>) -> Response {
    let engine = gw.engine();
    let ctx = gw.context();
    let mut visible: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (kind, pattern, _) in engine.catalog().entries() {
        if pattern.contains('*') {
            continue;
        }
        let a = assume_pinned(&engine, Action::new(kind.clone(), pattern.clone(), Value::Null));
        if engine.visible(&r.principal, &a, &ctx) {
            visible.entry(kind.to_string()).or_default().push(pattern.clone());
        }
    }
    Json(json!({"scopes": engine.effective_scopes(&r.principal), "visible": visible})).into_response()
}

async fn get_kill(State(gw): State<Gateway>) -> Response {
    Json(json!({"mode": gw.kill_switch()})).into_response()
}

#[derive(Deserialize)]
struct KillReq {
    mode: KillSwitch,
}

async fn set_kill(State(gw): State<Gateway>, Json(r): Json<KillReq>) -> Response {
    match gw.set_kill_switch(r.mode) {
        Ok(()) => {
            gw.record("kill_switch", json!({"mode": r.mode}));
            let _ = gw.list_changed.send(());
            Json(json!({"mode": gw.kill_switch()})).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn upstreams(State(gw): State<Gateway>) -> Response {
    let list: Vec<Value> =
        gw.upstreams.values().map(|u| json!({"name": u.name, "url": u.client.url(), "resource_prefixes": u.resource_prefixes})).collect();
    Json(json!({"upstreams": list})).into_response()
}

#[derive(Deserialize)]
struct TailQuery {
    #[serde(default = "default_n")]
    n: usize,
}

fn default_n() -> usize {
    50
}

async fn tail(State(gw): State<Gateway>, Query(q): Query<TailQuery>) -> Response {
    Json(json!({"events": gw.audit.tail(q.n.min(1000))})).into_response()
}

async fn policy(State(gw): State<Gateway>) -> Response {
    let e = gw.engine();
    Json(json!({"version": e.version(), "warnings": e.warnings(), "rules": e.rules().len()})).into_response()
}
