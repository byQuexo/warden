# Changelog

## Unreleased

* MCP client (`warden-mcp`) uses the official Rust SDK, [`rmcp` 3.9.0](https://github.com/modelcontextprotocol/rust-sdk).
  Streamable HTTP, stdio, initialize, and protocol-version selection go through the SDK. The gateway's
  own HTTP server, strict JSON ingress, and application codes `-32001` (forbidden) and `-32002`
  (upstream failure) stay custom. `-32002` collides with MCP's "resource not found"; the number is
  unchanged so existing clients keep matching it. Rust 1.88 or newer is required (was 1.82).
  The whole workspace moves to reqwest 0.13. Upstream sessions close after 15 minutes idle,
  a session that times out is replaced, and after a dropped connection only reads are re-sent
  (`tools/call` is never replayed).
* Token introspection (RFC 7662) for opaque tokens and instant revocation; the STS gains
  `/introspect`, `/revoke` (RFC 7009, revoke-by-subject) and a production `warden sts` command.
* stdio upstreams (child process, environment allow-list) next to Streamable HTTP.
* Per-upstream circuit breaker: unhealthy servers leave `tools/list`, calls fail fast, audited.
* OTLP audit sink (OpenTelemetry logs over HTTP/JSON).
* Read-only impersonation ("test as user"): STS `impersonate=`, `impersonation.read_only` in the
  engine, `context.impersonation` for rules, audited, generated attacks.
* A2A proxy: `upstream_exchange` exchanges the caller's token at a token service for one
  scoped to the upstream agent (same subject and `act` chain), so sub-agents can act for the
  user without ever holding the user's token.
* `subset_of` constraint: every element of a list argument must be in an attribute list.
* Confirmations: `approve_by: subject` on an `approve_if` rule lets the requesting subject
  confirm its own action (and only the subject); the webhook request carries
  `confirmation: true`. Ordinary approvals still refuse self-approval.
* `warden schema` and JSON Schemas for every config file; examples validate in editors.
* Reusable GitHub Action (`uses: byQuexo/warden@main`) and nightly cargo-fuzz.
* `examples/devtools` (GitHub, Postgres, Slack, files) and `warden bench`.

## 0.1.0 — 2026-11-05

First public version.

* Pure Rust decision engine: scopes ∩ agent ceiling ∩ token ∩ delegation chain, restrict-only
  rules, script-free constraint language with SQL guard, strict JSON, name/URI normalization,
  definition pinning, kill switch, lint, explainable traces.
* Identity: JWKS verification with OIDC discovery, claim-mapping presets (Keycloak, Auth0,
  Entra ID, Okta, generic OIDC), STS with token exchange and delegation chains.
* MCP gateway with per-principal list filtering, call enforcement, approvals, audit and admin API.
* Tamper-evident audit log with HMAC'd arguments and signed checkpoints.
* Security eval with generated attacks and mutation testing; CI gates.
* WebAssembly/TypeScript package with guard, MCP and AI SDK adapters.
* Examples: minimal starter, Acme reference with Keycloak and Docker Compose.
