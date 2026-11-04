# Threat model

## Assets and trust

| Component | Trust |
|---|---|
| Model output, tool results, ticket/document text | **untrusted** — may contain prompt injection |
| Upstream MCP servers | semi-trusted: reachable via config, but names, descriptions, schemas, annotations and results are untrusted |
| The agent application holding user tokens | trusted for those tokens; a compromised agent has the rights of its current tokens (bounded, not prevented) |
| Gateway, IdP, STS, policy files, audit keys | trusted computing base |

The goal is not to detect prompt injection but to make its consequences irrelevant: whatever
the model is talked into, it can only do what the user *and* the agent *and* the token *and*
every delegating agent are allowed to do, with the arguments the policy allows.

## Threats and mitigations

Each row references the test that demonstrates it (`e2e` = `crates/agent-scope-gateway/tests/e2e.rs`,
`ref` = `examples/acme/eval/reference.yaml`, `gen` = generated attacks).

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Forged tokens (`alg: none`, HS256 key confusion, tampered payload, unknown `kid`) | RS256/ES256/EdDSA only, key type must match alg, kid lookup with 1/min refresh limit | `identity/tests/tokens.rs`, TS `identity.test.ts` |
| T2 | Token for another audience / expired / not yet valid / ID token used as access token | core checks `aud`, `exp`, `nbf` (skew), `typ` | token vectors, `e2e::t_invalid_tokens…` |
| T3 | Token passthrough to upstreams | gateway only sends exchanged or service tokens | `e2e::a1…_t6_no_token_passthrough` |
| V1 | Model sees tools the user may not use | `tools/list` filtered per principal | `e2e::v1…`, ref V1 |
| V2 | Model calls an unlisted tool anyway | every call re-checked | `e2e::v2…`, ref V1 |
| V3 | Path traversal / double encoding in resource URIs | decode once, reject `..`, empty segments, residual `%` | `e2e::v3_v4…`, ref V4/V4b |
| A1 | Arguments outside the user's data (other unit, tenant) | `require` with principal placeholders | ref A1, A2, A2f |
| A2 | Type confusion (`"80000"`), missing arguments to skip a rule | unknown → deny, for every rule kind | ref A6/A6b, gen `G-ARG …` |
| A3 | Parser differential via duplicate JSON keys | strict parse, forward exactly what was checked | `e2e::a7…`, ref A7, gen `G-DUPKEY` |
| A4 | Look-alike values (zero-width space, bidi) | Cc/Cf characters in compared strings → deny | ref A8, gen `G-ARG … invisible` |
| A5 | SQL injection through a query tool | `sql` constraint: single SELECT, table/function allowlists over the AST | `e2e::a3_sql_guard`, ref A3/A3b |
| A6 | ReDoS | Rust `regex` (linear time) with size limit, payload size and depth caps | ref E16, json unit tests |
| D1 | Escalation through delegation (research agent borrows action agent's write) | intersection over every agent in `act` | `e2e::d_delegation…`, ref D1, gen `G-DELEG` |
| D2 | Forged or overlong chains | `act` only from `delegation_issuers`, edges and depth checked by STS *and* engine | token vectors, gen `G-DEPTH` |
| S1 | Session hijack (reuse another user's `Mcp-Session-Id`) | session bound to subject + agent + chain | `e2e::s1…` |
| S2 | Upstream asks the client's model to sample / elicit | server→client requests are answered with an error, never relayed | `e2e::s2…` |
| I1 | Homoglyph tool names (`crm.updаte_deal`) | NFKC + ASCII allowlist, collision check | `e2e::i3…`, ref I3, gen `G-HOMOGLYPH` |
| I2 | Upstream lies about risk (`readOnlyHint: true` on a write) | annotations come from the catalog only | `e2e::i3_…_i4…` |
| I3 | Rug pull: upstream changes a tool description/schema after review | definitions pinned in `catalog.lock`; changed or new → hidden and denied | `e2e::l3…` |
| P1 | Approval reused for different arguments | approval request carries `args_hash`; never cached; arguments forwarded as approved | `e2e::p_big_deals…` |
| P2 | Self-approval, approver timeout, approver down | denied | `e2e::p_big_deals…` |
| P3 | Token expires or policy changes while waiting for approval | re-check after approval | gateway `approve()` |
| L1 | Broken policy deployed | lint before swap; previous policy stays active | `e2e::l2…` |
| L2 | Policy weakened by mistake | eval gates + mutation testing in CI | `cli::eval_gate_fails_on_a_weakened_policy` |
| C1 | Emergency stop | kill switch (`writes` / `all`), file-based, admin API | `e2e::c1…` |
| C2 | Audit tampering (edit, delete, full recomputation) | hash chain + Ed25519-signed checkpoints | `audit` unit tests, `e2e::c3…` |
| C3 | Actions without audit trail | sink failure → deny | `e2e::c7…` |
| C4 | Engine bug or panic | `check` cannot return an error; panics → deny; WASM traps → deny + reinit | `engine::panicking_custom_constraint_fails_closed` |
| C5 | Insecure settings in production | plain-HTTP issuers, auto-approve, unsigned audit, missing HMAC key require `--dev` | `binary::insecure_settings_require_dev_flag` |

## Out of scope

* **Exfiltration within allowed actions.** If a user may read deals and the agent may send
  e-mail, the model can be tricked into mailing deals. Restrict combinations with agent
  ceilings and approvals; agent-scope does not inspect data flows.
* **Compromised agent process.** It holds valid tokens and can use them within policy.
* **Upstreams without their own authorization.** Defense in depth: the SQL constraint does not
  replace a read-only database role.
* **Denial of service / rate limiting.** Payload caps exist; quotas do not.
* **Prompt-injection detection.** Deliberately not attempted.
