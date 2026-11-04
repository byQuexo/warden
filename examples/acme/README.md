# Acme reference

A fictional company with HR, IT, sales and finance, four agents and a Keycloak realm. It is the
policy used by the demo, the end-to-end tests and the security-eval CI gate.

| File | Purpose |
|---|---|
| `catalog.yaml` | tools (`hr.*`, `crm.*`, `ticket.*`), resources (`docs://…`), prompts, an A2A skill and a custom `x-payment` kind |
| `policy.yaml` | 7 roles, 6 agents with delegation edges, 9 restricting rules |
| `catalog.lock` | pinned definitions of the mock MCP servers (`agent-scope catalog pull`) |
| `eval/reference.yaml` | 43 hand-written scenarios; CI requires 100% rule coverage and 100% killed mutants |
| `identity.yaml`, `gateway.yaml`, `compose.yaml`, `keycloak/` | the Docker stack below |

## Run with Keycloak

```bash
./smoke.sh                          # build, start and check the stack (KEEP=0 to tear down)
docker compose logs -f gateway      # watch decisions (stdout audit sink)
```

| Service | URL |
|---|---|
| Keycloak (admin/admin) | http://localhost:8080 |
| Gateway (MCP) | http://localhost:8088/mcp |
| Admin API (token `dev-admin-token`) | http://localhost:8089 |

Users (password `dev`): `hanna` (HR member), `henrik` (HR lead), `ivo` (IT), `ines` (IT admin),
`sven` (sales, tenant dach), `sara` (sales lead, dach + enterprise), `fiona` (finance).

```bash
TOKEN=$(curl -s localhost:8080/realms/acme/protocol/openid-connect/token \
  -d grant_type=password -d client_id=acme-bot -d client_secret=dev-bot-secret \
  -d username=henrik -d password=dev | jq -r .access_token)
```

Use the token with any MCP client against `http://localhost:8088/mcp`. The gateway talks to the
MCP servers with its own Keycloak service account (`agent-scope-gw`), never with your token.

## Evaluate the policy

```bash
cargo run -p agent-scope-cli -- eval --suite eval/reference.yaml --generate --mutate --coverage --gate
```

## Explain a decision

```bash
cargo run -p agent-scope-cli -- explain \
  --principal '{"subject":{"id":"sven","roles":["sales-rep"],"attrs":{"tenants":["dach"]}},"agent":"acme-bot"}' \
  --action tool:crm.update_deal --args '{"tenant":"dach","deal_id":"d-1","amount":80000}'
```
