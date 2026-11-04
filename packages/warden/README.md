# Warden (TypeScript)

Authorization for AI agents, in TypeScript. The decision engine is the
[warden](https://github.com/byQuexo/warden) Rust core compiled to WebAssembly, so it gives
exactly the same answers as the Rust gateway (shared conformance vectors run in both).

```ts
import { createScope, guard, verifyToken, ScopeDeniedError } from "warden";

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
| `warden` | `createScope`, `Scope.check/visible/filter`, `guard`, `lint`, types |
| `warden/identity` | `verifyToken`, `TokenVerifier` (jose for signatures, shared core for claims) |
| `warden/mcp` | `withScope` for your own MCP server handlers |
| `warden/ai-sdk` | `scopeTools` for Vercel AI SDK tool maps |

Build from source: `npm install && npm run build:wasm && npm test` (needs Rust with the
`wasm32-unknown-unknown` target and `wasm-bindgen-cli 0.2.130`).
