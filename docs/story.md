# The story behind Warden

## The problem

An AI agent with tools acts for a person. Today that usually means one of two things: the
agent gets a broad service token for each tool server and the prompt says what it may do, or
the user's own token is passed straight through to every server. In the first case every user
gets the union of everything; in the second, every MCP server holds credentials it should never
see. Neither can express "only in orgs this user belongs to", "only these two tables",
"a human confirms merges", or "a research agent called by a sales lead still cannot write".

And the decision is in the wrong place. A model that reads a malicious issue can be talked into
anything; if the model decides what is allowed, so can the attacker.

Warden answers one question in code, outside the model: *may this agent, acting for this user,
do this exact thing right now?*

## Why this architecture

- **A pure decision core.** `warden-core` has no I/O, no clock and no panics that escape. That
  makes it testable down to single decisions, lets it compile to WebAssembly (the same engine
  runs in a browser for "what if" checks), and lets Rust and TypeScript be proven identical
  with shared test vectors.
- **One formula for rights.** `user roles ∩ agent ceiling ∩ token scopes ∩ every agent in the
  delegation chain`. Delegation is in the token (`act` chain), so a sub-agent can never have
  more than the weakest link.
- **Rules can only restrict.** Roles grant; rules can deny, require arguments, or hold a call
  for a human (`approve_if`). No rule can widen rights, so a wrong rule fails closed.
  Unknown values always deny, even inside an approval rule.
- **A gateway in front of the tools.** The gateway lists only permitted tools, checks every
  call, exchanges the user's token for a narrow one per upstream (RFC 8693) and never forwards
  the user's token. It owns approvals: it holds the call, asks a human over a signed webhook,
  binds the approval to the exact arguments and checks again before forwarding.
- **Approval or confirmation.** By default an approval comes from someone else, and
  self-approval is refused (separation of duties). `approve_by: subject` turns a rule into a
  confirmation: only the user may answer, for writes an agent makes in their name.
- **Evidence, not claims.** Every decision goes into a hash-chained audit log with signed
  checkpoints; arguments are HMAC'd, not stored. `warden audit verify` checks the chain.

## What the tests show

| Claim | Evidence | What it does *not* prove |
|---|---|---|
| The engine decides as specified | conformance vectors run by Rust and TypeScript/WASM; unit tests on constraints, delegation, claims | That a given policy is the right policy |
| Policies hold under attack | `warden eval --generate` derives attacks from your own catalog and policy (scope boundaries, ceilings, delegation, mistyped and zero-width arguments, homoglyph tool names, duplicate JSON keys, kill switch); `--mutate` removes each rule and requires a case to fail | Attacks the generators do not know; it is systematic, not exhaustive |
| The gateway enforces it over real HTTP | end-to-end tests with real tokens and mock MCP servers; a Docker stack with Keycloak | Behaviour behind a real SaaS MCP server in production |
| Parsers do not fall over | nightly cargo-fuzz on normalization, strict JSON, policy parsing and engine checks | Absence of logic bugs; fuzzing finds crashes, not wrong answers |
| The README's demo is true | `warden demo` checks every verdict it prints and exits 1 on any difference; CI runs it | Anything beyond those seven scenes |

## What is simulated

- **The demo's servers are mocks** (GitHub, Postgres, Slack, files from `warden-testkit`), and
  the "coding agent" is the demo calling tools directly. No language model is involved: Warden's
  answer does not depend on who makes the call, so the demo shows exactly what an agent would
  get.
- **Tokens are real** (ES256 JWTs from Warden's token service or Keycloak), and so is the HTTP.
- **The example companies** (`examples/acme`, `examples/devtools`) are invented.

## What does not work yet

- **Exfiltration within allowed actions.** If an agent may read deals and send mail, it can
  mail deals. Ceilings, confirmations and approvals separate such capabilities; Warden does not
  inspect content.
- A compromised agent process holds valid user tokens and can use them within policy.
- Approvals hold the request open; durable approvals across restarts are future work.
- Rate limits, result redaction and a Cedar backend are not built ([roadmap](roadmap.md)).
- The nightly fuzz job was red for days, at first for a build reason (the prebuilt cargo-fuzz
  was sometimes a musl build and compiled for a target the runner lacks). Once the target was
  pinned, the URI fuzzer found a real gap within a second: `z.2://../` normalized to a URI that
  still contained `..`, because a dot segment in the *host* position was accepted.
  Policies with exact prefixes such as `file:///workspace/**` were never affected, but a file
  server that joins host and path could have been walked out of its root
  (`file://../etc/passwd`). Dot authorities are now rejected, with regression tests. That is
  what fuzzing is for, and why a red nightly job deserves a look even when it "is just CI".

## Try it

```bash
git clone https://github.com/byQuexo/warden && cd warden
cargo run -p warden-cli -- demo
```

Seven scenes in about a minute, ending in "every verdict as documented ✔". For a full assistant
built on Warden, with a UI, approvals inbox and real-model runs, see
[Steward](https://github.com/byQuexo/steward).
