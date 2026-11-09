# CLAUDE.md

Warden is a policy-enforcing gateway for MCP and A2A agent traffic: it decides per
user and per agent what a tool call may do, and records the decision in an audit log.
`CONTRIBUTING.md` is the source of truth for the house rules; this file is the short version
plus what is easy to get wrong.

## Commands

Run these before calling a change done (they are what CI runs):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -p warden-cli -- demo        # every verdict must match
```

If a dependency change needs `Cargo.lock` to move, build once without `--locked`, then
re-run the commands above with it. Touched `warden-core` or `packages/warden`? Also run
`(cd packages/warden && npm run build:wasm && npm test)`.

## Rules

* **Fail closed.** Every new error path ends in `deny`. A new extension point gets a test
  showing that its failure denies.
* **Restrict-only.** Nothing may let a rule grant access.
* **Tests with every behaviour change.** Engine semantics: add a case to
  `spec/vectors/edge/cases.yaml` (runs in Rust and TypeScript). Gateway behaviour: add a
  scenario to `crates/warden-gateway/tests/e2e.rs`.
* **No panics in library code.** `unwrap`, `expect` and `panic!` are denied by clippy outside
  tests. For a `std::sync::Mutex`, recover the guard from a poisoned lock rather than unwrap it.
* **MSRV is 1.88** (`rmcp`'s). Don't use std APIs newer than that, and don't use ones that are
  deprecated on current stable either, because CI builds with `-D warnings`.
* **One version per dependency.** Add to `[workspace.dependencies]` in the root `Cargo.toml` and
  use `dep.workspace = true`. `reqwest` is on 0.13 because `rmcp` is; keep them aligned.
* Formatting: `rustfmt.toml` sets `max_width = 140`.
* User-visible change: add a line under `## Unreleased` in `CHANGELOG.md`.
* Commits: short imperative subject, a body that explains *why*, one logical change each.

## Layout

| Crate | Role |
|---|---|
| `warden-core` | pure engine: model, catalog, policy, normalization, decisions. No clock, no I/O. |
| `warden-identity` | JWT/JWKS, introspection, token-exchange STS, attribute resolvers |
| `warden-audit` | hash-chained JSONL, HMAC'd args, Ed25519 checkpoints, OTLP sink |
| `warden-mcp` | upstream MCP client on `rmcp`, JSON-RPC helpers, SSE parser |
| `warden-gateway` | the enforcement point (custom axum MCP server) |
| `warden-a2a`, `warden-rig`, `warden-eval`, `warden-cli`, `warden-wasm` | A2A proxy, rig hook, eval runner, `warden` binary, WASM build of the core |

## The MCP client (`crates/warden-mcp`)

* `rmcp` owns the upstream wire protocol (Streamable HTTP, stdio, initialize, session ids). The
  gateway's *server* side stays custom on purpose: it authenticates, parses strict JSON (it
  rejects duplicate keys) and applies policy before anything else sees a call. Don't route
  inbound traffic through `rmcp`'s server.
* Only replay a request after a dropped connection if it is a read (`REPLAY_SAFE` in
  `client.rs`). `tools/call` may already have run upstream.
* Server→client requests (sampling, elicitation, roots, ping) are refused in `block.rs` and
  reported in `Outcome::blocked`. Don't fall back to `rmcp`'s defaults: an empty roots list
  or an elicitation decline both look like a user's answer.
* `order.rs` holds the inbound stream until the handler has recorded a server request or
  notification, so the audit event isn't lost. Each counted message must be released, or the
  `GRACE` backstop opens the gate. If you add a notification handler, drop a `NoteDone` in it.
* Error codes `-32001` (forbidden) and `-32002` (upstream failure) are Warden's. `-32002`
  collides with MCP's resource-not-found; existing clients rely on the number, so don't change it.
