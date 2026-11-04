# Status and roadmap

agent-scope is **0.1**: complete enough to run and evaluate end to end, not yet battle-tested
in production. The original design document (German) is in [design/plan-de.md](design/plan-de.md).

## Implemented

* Pure decision engine with catalog, policy, constraints (`equals`, `in`, `glob`, `regex`, `min`,
  `max`, `not_in_range`, `sql`, `all`/`any`, custom), delegation chains, kill switch, pinning, lint
* Claim mapping with presets for Keycloak, Auth0, Entra ID, Okta, generic OIDC
* JWKS verifier with OIDC discovery and kid-flood protection; STS with client credentials and
  RFC 8693 token exchange including `delegate_to` for `act` chains
* MCP gateway (Streamable HTTP): session binding, list filtering, call enforcement, strict
  argument parsing, payload caps, pinning, annotations from catalog, server→client request
  blocking, approvals via webhook with SSE progress, token exchange to upstreams, kill switch,
  hot reload, admin API, RFC 9728 metadata, `list_changed` notifications
* Tamper-evident audit (hash chain, HMAC'd arguments, Ed25519 checkpoints) and verifier
* Security eval: scenario runner, generated attacks, mutation testing, coverage, baselines, CI gates
* WebAssembly build and TypeScript package (guard, MCP server adapter, AI SDK adapter, jose verifier)
* Keycloak reference stack with Docker Compose

## Deviations from the design document

| Design | Implementation | Why |
|---|---|---|
| `rmcp` for MCP | own JSON-RPC/Streamable-HTTP layer on axum + reqwest | full control over parsing and forwarding; fewer moving parts |
| `agent-approval-gate` crate for approvals | `Approver` trait + versioned webhook protocol in the gateway | no dependency on an unpublished crate version |
| `rig` hook adapter | not included; use the core in-process (`Engine::check`) from any Rust agent loop | rig's hook API is pre-1.0 |
| A2A adapter crate | `a2a_skill` action kind in the core | adapter is a thin wrapper; kind is enough to evaluate |
| OpenTelemetry exporter | `TracingSink` emitting `tracing` events | plug into `tracing-opentelemetry` without pinning an OTEL stack |
| Introspection (RFC 7662), stdio upstreams, circuit breaker, result redaction | not yet | listed below |

## Next

* Token introspection for opaque tokens and instant revocation
* stdio upstreams and per-upstream health / circuit breaking
* Rate limits and quotas per principal
* Cedar as an alternative `Engine` backend; OpenFGA as an `AttributeResolver`
* Python bindings (PyO3) next to the WASM package
* Policy diff ("what changes for whom") and signed policy bundles
* LLM-driven attacker for nightly evals (scripted attacks run today)
