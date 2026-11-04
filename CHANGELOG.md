# Changelog

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
