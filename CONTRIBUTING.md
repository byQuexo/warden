# Contributing

Thanks for helping! A few conventions keep agent-scope trustworthy.

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd examples/acme && cargo run -q -p agent-scope-cli -- eval --suite eval/reference.yaml --generate --mutate --coverage --gate)
(cd packages/agent-scope && npm run build:wasm && npm test)   # if you touched the core or the TS package
```

## Rules of the house

* **Fail closed.** Every new error path must end in `deny`. If you add an extension point, add a
  test that its failure denies.
* **Restrict-only rules.** Features that would let a rule grant access will not be merged.
* **Tests with every behaviour change.** Engine semantics change → add a case to
  `spec/vectors/edge/cases.yaml` (it runs in Rust *and* TypeScript). Gateway behaviour change →
  add an end-to-end scenario in `crates/agent-scope-gateway/tests/e2e.rs`.
* **No panics in library code.** `unwrap`, `expect` and `panic!` are denied by clippy outside tests.
* **New IdP preset?** Add `crates/agent-scope-core/presets/<name>.yaml` and token vectors in
  `spec/vectors/tokens.yaml`; no Rust code needed.

## Commit style

Short imperative subject, body explaining the *why*. One logical change per commit.
