# Using agent-scope

Three ways in, same engine.

## 1. Gateway (any language, no code)

Put the gateway between your agents and your MCP servers.

```bash
agent-scope catalog pull --gateway gateway.yaml --dev   # discover tools, write catalog.lock + skeleton
# classify tools in catalog.yaml (scopes, sensitivity, tags), write policy.yaml
agent-scope lint && agent-scope eval --suite scenarios.yaml --generate --gate
agent-scope-gateway --config gateway.yaml
```

Agents connect to `http://gateway:8088/mcp` with the user's access token (OAuth 2.0 bearer).
Unauthenticated clients get `401` with RFC 9728 `resource_metadata`, so MCP clients can
discover the authorization server.

Operators use the admin API (separate port, bearer token):

| Endpoint | Purpose |
|---|---|
| `POST /v1/explain` `{principal, action, context?}` | full decision trace |
| `POST /v1/effective` `{principal}` | effective scopes and visible actions |
| `GET/POST /v1/kill` `{mode: off\|writes\|all}` | kill switch |
| `GET /v1/upstreams`, `GET /v1/policy`, `GET /v1/audit/tail?n=50` | status |

### Approval webhook protocol (v1)

`POST <url>` with `X-Agent-Scope-Signature: sha256=<hex hmac of body>` (if a secret is set):

```json
{"v":1,"id":"…","subject":"sven","agent":"acme-bot","act":[],"kind":"tool","name":"crm.update_deal",
 "args":{"tenant":"dach","deal_id":"d-1","amount":80000},"args_hash":"hmac-sha256:…",
 "rule":"big-deals-need-approval","reason":"…","policy_version":"sha256:…"}
```

Answer `{"decision": "approve" | "deny", "approver": "lead@acme", "reason": "…"}`. Optionally echo
`args_hash`; a mismatch fails the approval. The gateway rejects self-approval, re-checks the
policy and forwards exactly the approved arguments. Clients that send a `progressToken` and
accept SSE receive `notifications/progress` while waiting.

## 2. Rust, in-process

```rust
use agent_scope_core::{Action, Context, Effect, Engine};
use agent_scope_identity::Verifier;

let engine = Engine::builder()
    .policy_yaml(include_str!("policy.yaml"))
    .catalog_yaml(include_str!("catalog.yaml"))
    .build()?;                                     // lint errors = Err, never half-loaded

let verifier = Verifier::new(identity_config);
let principal = verifier.verify(bearer, agent_scope_identity::now_unix()).await?;

let d = engine.check(&principal, &Action::tool("crm.update_deal", args), &Context::default());
match d.effect {
    Effect::Allow => run().await,
    Effect::RequireApproval => ask_a_human(&d).await,
    Effect::Deny => return Err(d.model_message),   // never show d.reason to the model
}
```

Use `engine.filter(&principal, &ActionKind::Tool, names, &ctx)` to decide what to put into the
model's tool list, and `engine.explain(…)` / `Decision::render()` for debugging.

## 3. TypeScript (WebAssembly)

```ts
import { createScope, guard, verifyToken } from "agent-scope";
import { withScope } from "agent-scope/mcp";
import { scopeTools } from "agent-scope/ai-sdk";

const scope = createScope({ policyYaml, catalogYaml });
const principal = await verifyToken(bearer, { identityYaml });

// any function
const updateDeal = guard(scope, () => principal, "crm.update_deal", rawUpdateDeal, { approver });

// your own MCP server (@modelcontextprotocol/sdk)
const scoped = withScope({ listTools, callTool }, scope, { principal: (extra) => verifier.verify(extra.authInfo.token), prefix: "crm." });

// Vercel AI SDK tool map
const tools = scopeTools(scope, principal, { list_deals, update_deal }, { prefix: "crm." });
```

Build the package from source:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130
cd packages/agent-scope && npm install && npm run build:wasm && npm test
```

## Extending

* **Your IdP**: write a `mapping:` (JSON pointers) or add a preset YAML under
  `crates/agent-scope-core/presets/` plus token vectors in `spec/vectors/tokens.yaml`.
* **Attributes from a directory**: implement `agent_scope_identity::AttributeResolver`
  (async) or use the HTTP resolver (`attributes: { resolver: http, url: …/{subject.id} }`).
* **Audit destination**: implement `agent_scope_audit::AuditSink`; return an error to make the
  gateway fail closed.
* **Approvals**: implement `agent_scope_gateway::Approver` or speak the webhook protocol.
* **Custom argument checks**: `Engine::builder().custom("name", Arc::new(|v, p, ctx| Tri::True))`
  and `require: { arg: x, custom: name }` (Rust only; lint warns that the policy is not portable).
