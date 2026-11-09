<p align="center">
  <img alt="Warden: authorization for AI agents. Every tool call is checked against the user, the agent and the exact arguments, in a way the model cannot talk its way around." src="docs/assets/readme/banner.svg" width="100%">
</p>

<p align="center">
  <a href="https://github.com/byQuexo/warden/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/byQuexo/warden/ci.yml?style=for-the-badge&logo=githubactions&logoColor=white&label=CI"></a>
  <img alt="Rust" src="https://img.shields.io/badge/Rust-engine%20%2B%20gateway-B7410E?style=for-the-badge&logo=rust&logoColor=white">
  <img alt="TypeScript via WebAssembly" src="https://img.shields.io/badge/TypeScript-WASM-3178C6?style=for-the-badge&logo=typescript&logoColor=white">
  <img alt="MCP and A2A" src="https://img.shields.io/badge/MCP%20%C2%B7%20A2A-gateway-0d9488?style=for-the-badge">
  <a href="#license"><img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/License-MIT%20%7C%20Apache--2.0-10b981?style=for-the-badge"></a>
</p>

<p align="center">
  <img alt="0 policy violations across 216 scenario and generated attack cases · every policy rule load-bearing: deleting any one of the 14 rules makes a scenario fail · 14 µs per decision (p50) in one benchmark run" src="docs/assets/readme/metrics.svg" width="100%">
  <br>
  <sub>Gated in CI on every push: the <a href="examples/devtools/eval/reference.yaml">devtools</a> and <a href="examples/acme/eval/reference.yaml">acme</a> scenario suites plus attacks generated from each policy (<code>warden eval --generate --mutate --coverage --gate</code>). Latency from <code>warden bench</code> (release build, one core) is a snapshot, not a gate, and varies by machine. → <a href="#results">Results</a></sub>
</p>

<p align="center">
  <img alt="Output of cargo run -p warden-cli -- demo: seven scenes with ALLOW, DENY and APPROVAL verdicts and the deciding rule, ending with a verified audit chain, no token passthrough and every verdict as documented." src="docs/assets/screens/demo.png" width="760">
</p>

**In short:** an agent acting for a user may do exactly what that user may do, through that agent,
with those arguments, decided in code the model cannot talk to.

- **Problem.** Agents usually get one broad service token per tool server (every user gets the
  union) or the user's own token is passed through to every server. What the agent may do is
  then written in the prompt, and a prompt can be injected.
- **What Warden adds.** An MCP gateway (and the same engine as a Rust or TypeScript library)
  that checks every call against user × agent × delegation chain × exact arguments, holds risky
  writes for a human, gives each upstream its own narrow credential, and writes a
  hash-chained audit log.
- **What it is not.** Not a content filter or DLP (allowed actions can still move data), not a
  sandbox for the agent process, not an identity provider or hosted service, and not
  production-hardened: one process, state in memory. See [Known limits](#known-limits).

[Why it exists, what the tests prove and what they don't, and what is simulated](docs/story.md).
[Steward](https://github.com/byQuexo/steward) is a full assistant built on Warden (UI, approvals
inbox, real-model runs) and serves as its demo application;
[agent-approval-gate](https://github.com/byQuexo/agent-approval-gate) is the smaller
predecessor that only gates approvals.

## Try it

```bash
git clone https://github.com/byQuexo/warden && cd warden
cargo run -p warden-cli -- demo
```

One command boots an OIDC token service, MCP servers for **GitHub, Postgres, Slack and workspace files**,
an approval webhook and the gateway, then plays through what a coding agent tries to do, with
real tokens over real HTTP:

```text
1  The coding agent only sees the tools its user may use (tools/list is filtered)
   vic    viewer      github.list_issues, postgres.query
   dana   developer   github.create_issue, github.list_issues, github.merge_pull_request, postgres.query
   mo     maintainer  github.create_issue, github.list_issues, github.merge_pull_request, postgres.query
   mo may delete repos and post to Slack, but not through the coding agent (agent ceiling)

2  Arguments are checked, not just tool names
   dana   github.create_issue {owner: someone-else}                    DENY     own-orgs-only
   dana   github.create_issue {owner: "acme-dev​"}                DENY     own-orgs-only
   dana   postgres.query "…; DROP TABLE deployments"                   DENY     read-only-sql
   dana   postgres.query "SELECT … FROM users"                         DENY     read-only-sql

3  Prompt injection cannot widen rights
   mo     github.delete_repo (never listed, called anyway)             DENY     scope.missing

4  Human in the loop for risky writes
   dana   github.merge_pull_request {number: 42}                       APPROVAL
            ↳ approved by lead@acme-dev, re-checked, forwarded         ALLOW

5  Files: workspace yes, secrets no
   dana   resources/read file:///workspace/.env                        DENY     scope.missing
   dana   resources/read file:///workspace/../etc/passwd               DENY     normalize.uri

6  Supply chain: an MCP server silently changes a tool
   dana   github.create_issue (description changed; listed: false)     DENY     catalog.unpinned

8  Evidence
   audit log: 18 events, 2 signed checkpoints — chain verified ✔
   MCP servers received 4 calls, none with a user's token — token passthrough: none ✔
   every verdict as documented ✔
```

The block above is an excerpt (the ALLOW rows and scene 7, the kill switch, are cut). The demo
compares every verdict with the list in [`demo.rs`](crates/warden-cli/src/demo.rs) and exits 1
on any difference; CI runs it on every push. Everything in it is in-process and simulated: the
GitHub, Postgres, Slack and file servers are mocks, the "coding agent" is the demo script
calling tools, and every service listens on a random `127.0.0.1` port and stops when the demo
ends. No model is involved; Warden decides the same way whoever makes the call.

**One case in detail.** Scene 4: `dana` (developer) asks the coding agent to merge PR 42. The
rule `merges-need-approval` returns `require_approval`; the gateway holds the call, sends the
exact arguments and their HMAC to the approval webhook, `lead@acme-dev` approves, the gateway
checks the policy again and only then forwards the call to the GitHub mock with a token
exchanged for that upstream, never dana's own token. The audit log records the request, the
approval and the decision.

## Three ways to use it

| Gateway, no code | Rust, in-process | TypeScript, in-process |
|---|---|---|
| Put `warden-gateway` in front of the MCP servers you already run. Agents connect with the user's OAuth token. [Quickstart](#quickstart) | `warden-core` in your own loop, `ScopeHook` for [rig](https://github.com/0xPlaygrounds/rig) agents, `warden-a2a` for agent-to-agent calls. [Rust guide](docs/consuming.md#2-rust-in-process) | The same engine as WebAssembly: `guard()` any function, wrap your MCP server, or filter Vercel AI SDK tools. [TS guide](packages/warden/README.md) |

## What makes it different

Most agent frameworks hand every tool to every user and hope the prompt holds. Warden
answers *may this agent, acting for this user, do this exact thing right now?* in code:

```text
effective = user roles ∩ agent ceiling ∩ token scopes ∩ every agent in the delegation chain
decision  = scope gate → rules that can only restrict → allow | require_approval | deny
```

A policy is three small YAML files. Here is the heart of [`examples/devtools`](examples/devtools):

```yaml
# catalog.yaml: what exists and what it needs. Anything not listed is denied.
tool:
  github.create_issue:       { scopes: [github:write], sensitivity: write }
  github.merge_pull_request: { scopes: [github:write], sensitivity: write, tags: [release] }
  postgres.query:            { scopes: [db:read] }

# policy.yaml: roles grant scopes, agents have a ceiling, rules only ever restrict.
roles:
  developer: [github:read, github:write, db:read]
agents:
  coding-agent: { max: [github:read, github:write, db:read] }
rules:
  - id: own-orgs-only
    match: { kind: tool, name: "github.*" }
    require: { arg: owner, in: "{subject.attrs.orgs}" }
  - id: merges-need-approval
    match: { tag: release }
    approve_if: always
  - id: read-only-sql
    match: { kind: tool, name: postgres.query }
    require: { arg: sql, sql: { dialect: postgres, tables_allow: [issues, deployments] } }
```

Every decision can be explained, and the model only ever sees a generic sentence:

```text
$ warden explain --principal @dana.json --action tool:github.create_issue --args '{"owner":"someone-else","repo":"api","title":"x"}'
effect: deny
rule:   own-orgs-only
trace:
  normalize              ok         tool github.create_issue
  principal              ok         subject=dana agent=coding-agent
  catalog                ok         needs [github:write] sensitivity=Write tags=[]
  scope_gate             ok         github:write
  rule:own-orgs-only     deny       require — required condition does not hold
model sees: This action is not permitted.
```

## Why not just fine-grained tokens?

Use them: Warden gives each upstream its own narrow credential and never forwards the user's
token. But a token describes what a *credential* may do, and an agent setup needs answers a
token cannot give:

| | Fine-grained token | Warden |
|---|---|---|
| **Who** | one token per MCP server, shared by every user and agent behind it, so everyone gets the union | decides per user × agent × delegation chain, from the user's own OAuth token |
| **What exactly** | "write issues in repo X" | "only in orgs the user belongs to", "SELECT on these two tables", "post only to #deploys", "refunds up to 500 €" |
| **Who else** | none | `approve_if`: a human confirms the merge, with the exact arguments that will run |
| **Agent → agent** | the second agent has its own, usually broader, token | the chain is in the token and the ceiling of every agent in it applies |
| **Where** | per vendor, if the vendor has them at all (internal APIs often have one API key) | one policy for every MCP server, A2A agent or in-process function |
| **Afterwards** | vendor logs, if any, showing the service account | one signed audit log: user, agent, chain, action, arguments (HMAC'd), decision, rule |

The demo uses GitHub, Postgres and Slack only because everyone knows them. Nothing in the core
knows about any product: actions, roles, scopes, agents and attributes all come from your YAML,
so the same files describe a ticketing system, a payments API, an HR tool or a shell. Custom
action kinds (`x-payment`, `x-shell`, …) work exactly like MCP tools.

## Architecture

<img alt="Agents call the Warden gateway with the user's token; it verifies the token, filters lists, checks every call, asks a human when needed, audits, and forwards the checked arguments with its own credential. The same pure engine runs in the gateway, the rig hook, the A2A proxy and the TypeScript package." src="docs/assets/readme/architecture.svg" width="100%">

One pure Rust engine, no I/O and no clock, is shared by every entry point. The gateway adds
identity, sessions, approvals, pinning and audit around it. Details: [docs/architecture.md](docs/architecture.md).

<details>
<summary>Request flow (Mermaid)</summary>

```mermaid
sequenceDiagram
    participant C as Agent (MCP client)
    participant G as warden gateway
    participant E as warden-core
    participant A as Approver
    participant U as MCP server
    C->>G: initialize (Bearer user token)
    G->>G: verify JWT (JWKS) → principal, bind session
    C->>G: tools/list
    G->>U: tools/list (gateway credential)
    G->>E: normalize · pin check · visible?
    G-->>C: only permitted tools
    C->>G: tools/call github.merge_pull_request
    G->>G: strict JSON parse (duplicate keys → 400)
    G->>E: check → require_approval
    G->>A: webhook (args + args_hash), progress to C
    A-->>G: approved by lead
    G->>E: re-check (token valid? policy unchanged?)
    G->>U: tools/call with the checked arguments, exchanged token
    G->>G: audit (hash chain, signed checkpoints)
    G-->>C: result
```
</details>

## Results

The eval table is a CI gate on every push (job `security-eval` in
[ci.yml](.github/workflows/ci.yml)); reproduce it from the example directory with
`warden eval --suite eval/reference.yaml --generate --mutate --coverage --gate`.

| Suite | Hand-written | Generated attacks | Passed | Rule coverage | Rules load-bearing |
|---|---|---|---|---|---|
| [devtools](examples/devtools/eval/reference.yaml) (GitHub, Postgres, Slack, files) | 23 | 51 | **74 / 74** | 5 / 5 | 5 / 5 |
| [acme](examples/acme/eval/reference.yaml) (enterprise HR, CRM, tickets, Keycloak) | 43 | 99 | **142 / 142** | 9 / 9 | 9 / 9 |

Hard gates, all **0**: `scope_violation` (allowed what must be denied), `unapproved_write`,
`delegation_escalation`, failed cases, baseline regressions.

- **Rule coverage:** every rule both fires and holds back in at least one case.
- **Rules load-bearing** (`--mutate`, reported as `mutation_score`): every policy rule is
  load-bearing, i.e. deleting any single rule makes at least one hand-written scenario fail
  ([`mutation.rs`](crates/warden-eval/src/mutation.rs)). This is rule-deletion only. Conditions
  and thresholds are not mutated, and the suites do not pin every boundary: raising the acme
  approval threshold `min: 50000` to `50001` still passes all gates.

| What | Result | Reproduce |
|---|---|---|
| Rust tests (unit, conformance, end-to-end, CLI, binary, rig, A2A, schemas) | all pass, no services needed | `cargo test --workspace` |
| End-to-end gateway scenarios over real HTTP (mock MCP servers, real JWTs) | all pass | `cargo test -p warden-gateway --test e2e` |
| Conformance vectors run by Rust **and** TypeScript/WASM | **88** decisions + **17** tokens (5 IdP presets) | `cargo test -p warden-eval --test conformance`; `npm test` in `packages/warden` |
| Keycloak stack in Docker (real tokens through the gateway) | **8 / 8** smoke checks (CI job `acme-stack`) | `KEEP=0 ./examples/acme/smoke.sh` |
| Decision latency, 100k decisions, release build | p50 **14 µs**, p99 **45 µs** in an earlier run; four runs on a Windows laptop (2026-11-09): p50 14–28 µs, p99 59–128 µs. Not a gate; depends on machine and load | `warden bench --suite eval/reference.yaml` in `examples/devtools` |

<details>
<summary><b>What the generated attacks try</b></summary>

`warden eval --generate` reads *your* catalog and policy and derives cases whose expected
answer follows from the rules, not from running the engine:

| Generator | Example |
|---|---|
| Scope boundaries | a principal holding every scope except the one an action needs |
| Agent ceilings | each agent tries each action above its `max` |
| Delegation | every agent pair without a `may_delegate_to` edge; chains deeper than `max_depth` |
| Arguments | each constrained argument missing, mistyped (`"80000"`), or with a zero-width space |
| Names | homoglyph variants of every tool (`deletе_repo`) |
| Parser | duplicate JSON keys |
| Controls | kill switch on every write; every write from a test-as-user session; service tokens when not allowed |
</details>

## Design and limits

<details>
<summary>Design decisions</summary>

- **Pure core.** No I/O, no clock, no panics escape: it compiles to WebAssembly, and Rust and
  TypeScript give identical answers, proven by shared vectors.
- **Signature outside, semantics inside.** Only key handling lives outside the core; issuer,
  audience, expiry, token type, `act` chain and claim mapping are one implementation.
- **Restrict-only rules, deny-by-default, fail closed.** Panics, audit failures, approver
  timeouts and unknown values all end in `deny`.
- **Own MCP server and A2A layer** on axum instead of an SDK, to control every byte the gateway
  accepts and forwards (strict parsing, server→client request blocking, size caps). The upstream
  MCP client uses the official SDK, `rmcp`.
- **Catalog annotations, not upstream ones.** An MCP server claiming `readOnlyHint: true` on a
  write tool changes nothing.
- **Generic messages to the model.** Rule names and reasons help an attacker iterate, so they go to
  the audit log, not the model.
</details>

### Known limits

- **State is in memory and ephemeral.** MCP sessions live in a map inside the gateway process
  ([`gateway.rs`](crates/warden-gateway/src/gateway.rs), `sessions`), with no expiry and no
  persistence: a restart drops every session and clients must `initialize` again. Pending
  approvals are held open inside the request (progress notifications, default timeout 120 s):
  a timeout ends as `deny`, a restart drops the request without forwarding it, and there is no
  durable approval queue to resume from. The kill
  switch is in memory too unless `kill_switch.file` is configured. Only the audit log, the
  policy files and `catalog.lock` are on disk.
- **Single process.** No shared state between gateway replicas, so sessions do not survive a
  load balancer switching instances.
- **The demo is local and simulated.** `warden demo` and the "run locally" setup below use mock
  MCP servers, a dev token service and loopback addresses. `--dev` additionally allows plain-HTTP
  issuers on non-loopback hosts, the `auto-approve` approver and an audit log without HMAC key or
  signed checkpoints; the gateway refuses those settings without it
  ([`config.rs`](crates/warden-gateway/src/config.rs)).
- **Exfiltration within allowed actions** is out of scope: if an agent may read deals and send
  mail, it can mail deals. Use agent ceilings and approvals to separate such capabilities.
- A compromised agent process still holds valid user tokens and can use them within policy.
- Rate limits, result redaction and a Cedar backend are not built yet; see
  [roadmap](docs/roadmap.md).

<details>
<summary>Project layout</summary>

```
warden/
├── crates/
│   ├── warden-core/       # pure engine: model, catalog, policy, constraints, delegation, claims, lint
│   ├── warden-identity/   # JWKS verifier, introspection, STS with act chains + revocation, resolvers
│   ├── warden-audit/      # hash-chained JSONL, HMAC'd args, Ed25519 checkpoints, OTLP sink, verifier
│   ├── warden-mcp/        # MCP client on the official Rust SDK (rmcp), plus JSON-RPC helpers
│   ├── warden-gateway/    # the MCP gateway (binary + library) and its end-to-end tests
│   ├── warden-a2a/        # A2A proxy: per-caller agent cards, skill enforcement, task ownership
│   ├── warden-rig/        # ScopeHook for rig agents
│   ├── warden-eval/       # scenario runner, attack generator, mutation testing, CI gates
│   ├── warden-cli/        # `warden`: init, lint, explain, eval, bench, audit, catalog, sts, schema, dev, demo
│   ├── warden-testkit/    # deterministic mock MCP servers and approver (`mock-mcp`)
│   └── warden-wasm/       # WebAssembly bindings
├── packages/warden/       # npm package: WASM engine, guard(), MCP + AI SDK adapters, jose verifier
├── examples/
│   ├── minimal/           # 20-line starter (what `warden init` writes)
│   ├── devtools/          # coding agents on GitHub, Postgres, Slack, files (the demo)
│   └── acme/              # enterprise reference with Keycloak and Docker Compose
├── spec/
│   ├── vectors/           # cross-language conformance vectors
│   └── schema/            # JSON Schemas for every config file (generated, checked in CI)
├── fuzz/                  # cargo-fuzz targets, run nightly
├── action.yml             # reusable GitHub Action: `uses: byQuexo/warden@main`
└── docs/                  # architecture, policy reference, threat model, usage, roadmap
```
</details>

<details>
<summary>Development</summary>

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                          # no services needed; cargo prints the counts
(cd examples/devtools && cargo run -p warden-cli -- eval --suite eval/reference.yaml --generate --mutate --coverage --gate)
(cd packages/warden && npm install && npm run build:wasm && npm test)   # needs wasm-bindgen-cli 0.2.130
KEEP=0 ./examples/acme/smoke.sh                 # Keycloak stack, needs Docker
```

CI (GitHub Actions) runs fmt, clippy, all tests, the security-eval gates for both example
policies with the report in the job summary, the reusable action against the minimal example,
the WASM/TypeScript build and conformance tests, and the Docker/Keycloak smoke test. A nightly
workflow fuzzes name/URI normalization, strict JSON, policy parsing and decisions.
</details>

## Quickstart

Requirements: Rust 1.88+ (`rustup`). Docker only for the Keycloak stack, Node 18+ only for the
TypeScript package.

```bash
cargo install --git https://github.com/byQuexo/warden warden-cli warden-gateway
warden init my-agents && cd my-agents        # policy, catalog, identity, scenarios, all commented
```

1. **List your MCP servers** under `upstreams:` in a `gateway.yaml` (copy
   [`examples/devtools/gateway.yaml`](examples/devtools/gateway.yaml)).
2. **Discover their tools:** `warden catalog pull --gateway gateway.yaml` writes `catalog.lock`
   and a catalog skeleton where every tool starts *denied*. Give each one scopes and a sensitivity.
3. **Write roles, agents and rules** in `policy.yaml`, then prove them:
   `warden lint && warden eval --suite scenarios.yaml --generate --mutate --coverage --gate`.
4. **Trust your IdP** in `identity.yaml`: Keycloak, Auth0, Entra ID, Okta or any OIDC provider via
   a preset or a JSON-pointer mapping.
5. **Run it:** `warden-gateway --config gateway.yaml` and point your agents at `http://…:8088/mcp`.

<details>
<summary>Run the devtools example locally (no Docker)</summary>

```bash
cargo build --release && cd examples/devtools
for p in github:9101 postgres:9102 slack:9103 files:9104; do ../../target/release/mock-mcp --profile ${p%:*} --port ${p#*:} & done
../../target/release/warden dev sts --config sts.yaml &                 # dev OIDC issuer on :9400
eval "$(../../target/release/warden audit keygen)"
AUDIT_HMAC_KEY=dev AUDIT_SIGNING_KEY=$AUDIT_SIGNING_KEY WARDEN_ADMIN_TOKEN=dev \
  ../../target/release/warden-gateway --config gateway.yaml --dev

../../target/release/warden dev token --config sts.yaml --subject dana --agent coding-agent \
  --roles developer --attrs '{"orgs":["acme-dev"]}' --audience http://127.0.0.1:8088/mcp
```

Use the token with any MCP client (e.g. MCP Inspector) against `http://127.0.0.1:8088/mcp`.
</details>

<details>
<summary>Enterprise reference with Keycloak (Docker)</summary>

```bash
./examples/acme/smoke.sh     # Keycloak + gateway + MCP servers + approver, then 8 checks with real tokens
```

Realm `acme`, users `hanna`, `henrik`, `sven`, `sara`, … (password `dev`). See
[examples/acme](examples/acme/README.md).
</details>

<details>
<summary>TypeScript</summary>

```ts
import { createScope, guard } from "warden";

const scope = createScope({ policyYaml, catalogYaml });
const mergePr = guard(scope, () => principal, "github.merge_pull_request", rawMergePr, { approver });
await mergePr({ owner: "acme-dev", repo: "api", number: 42 }); // asks a human first
```

Adapters for your own MCP server (`warden/mcp`) and the Vercel AI SDK (`warden/ai-sdk`) are
included. See [packages/warden](packages/warden/README.md).
</details>

## Docs

[Story](docs/story.md) · [Architecture](docs/architecture.md) · [Policy reference](docs/policy-reference.md) ·
[Threat model](docs/threat-model.md) (every threat mapped to its test) ·
[Using Warden from Rust, TypeScript or any MCP client](docs/consuming.md) · [Roadmap](docs/roadmap.md)

Developed in an agentic development workflow.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
