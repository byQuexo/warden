# Minimal example

One MCP server (`ticket`), two roles, one agent, one rule. `agent-scope init` writes these files.

```bash
agent-scope lint
agent-scope eval --suite scenarios.yaml --generate --mutate --coverage --gate
```

Run it for real (from this directory, after `cargo build --release` at the repo root):

```bash
../../target/release/agent-scope dev sts --config sts.yaml &          # dev OIDC issuer, :9400
../../target/release/mock-mcp --profile ticket --port 9001 &          # the MCP server
eval "$(../../target/release/agent-scope audit keygen)"
AUDIT_HMAC_KEY=dev AUDIT_SIGNING_KEY=$AUDIT_SIGNING_KEY AGENT_SCOPE_ADMIN_TOKEN=dev \
  ../../target/release/agent-scope-gateway --config gateway.yaml --dev

../../target/release/agent-scope dev token --config sts.yaml --subject vera --agent helpdesk-bot \
  --roles viewer --audience http://127.0.0.1:8088/mcp     # vera sees ticket.list only
```

Audit files land in `./audit`; verify them with
`agent-scope audit verify audit --pubkey $AUDIT_PUBLIC_KEY`.
