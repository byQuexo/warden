# Minimal example

One MCP server (`ticket`), two roles, one agent, one rule. `warden init` writes these files.

```bash
warden lint
warden eval --suite scenarios.yaml --generate --mutate --coverage --gate
```

Run it for real (from this directory, after `cargo build --release` at the repo root):

```bash
../../target/release/warden dev sts --config sts.yaml &          # dev OIDC issuer, :9400
../../target/release/mock-mcp --profile ticket --port 9001 &          # the MCP server
eval "$(../../target/release/warden audit keygen)"
AUDIT_HMAC_KEY=dev AUDIT_SIGNING_KEY=$AUDIT_SIGNING_KEY WARDEN_ADMIN_TOKEN=dev \
  ../../target/release/warden-gateway --config gateway.yaml --dev

../../target/release/warden dev token --config sts.yaml --subject vera --agent helpdesk-bot \
  --roles viewer --audience http://127.0.0.1:8088/mcp     # vera sees ticket.list only
```

Audit files land in `./audit`; verify them with
`warden audit verify audit --pubkey $AUDIT_PUBLIC_KEY`.
