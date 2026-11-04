// Runs the shared conformance vectors (spec/vectors/manifest.yaml) through the WASM engine.
// The Rust test suite runs the very same files: identical results in both languages.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { parse } from "yaml";
import { createScope, type Action, type Context, type Principal } from "../index";
import { principalFromClaims, TokenError } from "../identity";

const root = path.resolve(__dirname, "../../../..");
const read = (p: string) => readFileSync(path.join(root, p), "utf8");

interface Case {
  id: string;
  as?: string;
  principal?: Principal;
  action: Action;
  args_raw?: string;
  context?: Context;
  expect: { effect?: string; rule?: string; visible?: boolean };
}

const manifest = parse(read("spec/vectors/manifest.yaml")) as {
  decision_suites: { policy: string; catalog: string; suite: string }[];
  token_vectors: string;
};

for (const ref of manifest.decision_suites) {
  test(`decision vectors: ${ref.suite}`, () => {
    const scope = createScope({ policyYaml: read(ref.policy), catalogYaml: read(ref.catalog) });
    const suite = parse(read(ref.suite)) as { principals?: Record<string, Principal>; cases: Case[] };
    assert.ok(suite.cases.length > 0);
    for (const c of suite.cases) {
      const p = c.principal ?? suite.principals?.[c.as ?? ""];
      assert.ok(p, `${c.id}: principal`);
      const action: Action = c.args_raw ? { ...c.action, argsRaw: c.args_raw } : c.action;
      const d = scope.check(p, action, c.context);
      if (c.expect.effect) assert.equal(d.effect, c.expect.effect, `${c.id}: effect (${d.rule}: ${d.reason})`);
      if (c.expect.rule) assert.equal(d.rule, c.expect.rule, `${c.id}: rule`);
      if (c.expect.visible !== undefined) assert.equal(scope.visible(p, action, c.context), c.expect.visible, `${c.id}: visible`);
    }
  });
}

test("token vectors", () => {
  const v = parse(read(manifest.token_vectors)) as {
    identity: string;
    cases: { id: string; now: number; claims: unknown; expect: { ok?: any; error?: string } }[];
  };
  for (const c of v.cases) {
    if (c.expect.error) {
      assert.throws(() => principalFromClaims(v.identity, c.claims, c.now), (e: unknown) => e instanceof TokenError && e.code === c.expect.error, c.id);
      continue;
    }
    const p = principalFromClaims(v.identity, c.claims, c.now);
    const ok = c.expect.ok;
    assert.equal(p.subject.id, ok.subject, c.id);
    assert.equal(p.subject.kind, ok.kind, c.id);
    assert.equal(p.agent, ok.agent, c.id);
    assert.deepEqual([...(p.subject.roles ?? [])].sort(), [...ok.roles].sort(), c.id);
    assert.deepEqual([...(p.token_scopes ?? [])].sort(), [...ok.scopes].sort(), c.id);
    assert.deepEqual(p.act, ok.act, c.id);
    for (const [k, want] of Object.entries(ok.attrs ?? {})) assert.deepEqual(p.subject.attrs?.[k], want, `${c.id} attr ${k}`);
  }
});
