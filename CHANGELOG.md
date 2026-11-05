# Changelog

## Unreleased

* Token introspection (RFC 7662) for opaque tokens and instant revocation; the STS gains
  `/introspect`, `/revoke` (RFC 7009, revoke-by-subject) and a production `warden sts` command.
* stdio upstreams (child process, environment allow-list) next to Streamable HTTP.
* Per-upstream circuit breaker: unhealthy servers leave `tools/list`, calls fail fast, audited.
* OTLP audit sink (OpenTelemetry logs over HTTP/JSON).
* Read-only impersonation ("test as user"): STS `impersonate=`, `impersonation.read_only` in the
  engine, `context.impersonation` for rules, audited, generated attacks.
* `subset_of` constraint: every element of a list argument must be in an attribute list.
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
