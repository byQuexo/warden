# agent-scope (TypeScript)

Authorization for AI agents, in TypeScript. The decision engine is the
[agent-scope](https://github.com/byQuexo/agent-scope) Rust core compiled to WebAssembly, so it gives
exactly the same answers as the Rust gateway (shared conformance vectors run in both).

```ts
import { createScope, guard, verifyToken, ScopeDeniedError } from "agent-scope";

const scope = createScope({ policyYaml, catalogYaml });
const principal = await verifyToken(bearerToken, { identityYaml });

const updateDeal = guard(scope, () => principal, "crm.update_deal", rawUpdateDeal, {
  approver: async ({ action }) => askSlack(action),        // for require_approval decisions
});

try {
  await updateDeal({ tenant: "dach", deal_id: "d-1", amount: 80000 });
} catch (e) {
  if (e instanceof ScopeDeniedError) return e.message;     // safe to show to the model
  throw e;
}
```

| Import | What |
|---|---|
| `agent-scope` | `createScope`, `Scope.check/visible/filter`, `guard`, `lint`, types |
| `agent-scope/identity` | `verifyToken`, `TokenVerifier` (jose for signatures, shared core for claims) |
| `agent-scope/mcp` | `withScope` for your own MCP server handlers |
| `agent-scope/ai-sdk` | `scopeTools` for Vercel AI SDK tool maps |

Build from source: `npm install && npm run build:wasm && npm test` (needs Rust with the
`wasm32-unknown-unknown` target and `wasm-bindgen-cli 0.2.130`).
