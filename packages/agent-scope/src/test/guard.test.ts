import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createScope, guard, lint, scopeTools, ScopeDeniedError, withScope, type Principal } from "../index";

const acme = path.resolve(__dirname, "../../../../examples/acme");
const scope = createScope({
  policyYaml: readFileSync(path.join(acme, "policy.yaml"), "utf8"),
  catalogYaml: readFileSync(path.join(acme, "catalog.yaml"), "utf8"),
});
const sven: Principal = { subject: { id: "sven", roles: ["sales-rep"], attrs: { tenants: ["dach"] } }, agent: "acme-bot" };
const hanna: Principal = { subject: { id: "hanna", roles: ["hr-member"], attrs: { org_unit: "hr" } }, agent: "acme-bot" };

test("lint and version", () => {
  assert.match(scope.version, /^sha256:/);
  assert.deepEqual(lint("version: 1\ndefaults: { effect: allow }\n", "version: 1\n").filter((f) => f.level === "error").length, 1);
  assert.throws(() => createScope({ policyYaml: "version: 1\ndefaults: { effect: allow }\n", catalogYaml: "version: 1\n" }));
});

test("guard allows, denies and never calls the function on deny", async () => {
  const calls: unknown[] = [];
  const listDeals = guard(scope, () => sven, "crm.list_deals", async (args: { tenant: string }) => {
    calls.push(args);
    return `deals of ${args.tenant}`;
  });
  assert.equal(await listDeals({ tenant: "dach" }), "deals of dach");
  await assert.rejects(listDeals({ tenant: "enterprise" }), (e: unknown) => e instanceof ScopeDeniedError && e.message === "This action is not permitted." && e.decision.rule === "tenant-pinning");
  assert.equal(calls.length, 1);
});

test("approvals: required, bound to the checked args, never self-approved", async () => {
  let seen: unknown;
  const updateDeal = guard(
    scope,
    () => sven,
    "crm.update_deal",
    async (args: { tenant: string; deal_id: string; amount: number }) => {
      seen = args;
      return "updated";
    },
    { approver: async () => ({ approved: true, approver: "lead@acme" }) },
  );
  const args = { tenant: "dach", deal_id: "d-1", amount: 80000 };
  assert.equal(await updateDeal(args), "updated");
  assert.ok(Object.isFrozen(seen), "the function receives a frozen copy of what was approved");
  assert.notEqual(seen, args);

  const selfApproved = guard(scope, () => sven, "crm.update_deal", async () => "updated", { approver: async () => ({ approved: true, approver: "sven" }) });
  await assert.rejects(selfApproved(args), ScopeDeniedError);
  const noApprover = guard(scope, () => sven, "crm.update_deal", async () => "updated");
  await assert.rejects(noApprover(args), ScopeDeniedError);
});

test("strict argument parsing reaches TypeScript too", () => {
  const d = scope.check(sven, { kind: "tool", name: "crm.list_deals", argsRaw: '{"tenant":"dach","tenant":"enterprise"}' });
  assert.equal(d.effect, "deny");
  assert.equal(d.rule, "normalize.args");
});

test("MCP adapter filters lists and enforces calls", async () => {
  const handlers = {
    listTools: () => [{ name: "search_employees" }, { name: "get_salary" }],
    callTool: async (name: string) => ({ content: [{ type: "text", text: `${name} ran` }] }),
  };
  const scoped = withScope(handlers, scope, { principal: () => hanna, prefix: "hr." });
  assert.deepEqual((await scoped.listTools()).map((t) => t.name), ["search_employees"]);
  const denied = await scoped.callTool("get_salary", { unit: "hr" });
  assert.equal(denied.isError, true);
  const ok = await scoped.callTool("search_employees", { query: "x" });
  assert.equal(ok.content[0]?.text, "search_employees ran");
});

test("AI SDK adapter hides tools and guards execute", async () => {
  const tools = scopeTools(
    scope,
    sven,
    {
      list_deals: { description: "list", execute: async (a: { tenant: string }) => `deals ${a.tenant}` },
      export_deals: { description: "export", execute: async () => "csv" },
    },
    { prefix: "crm." },
  );
  assert.deepEqual(Object.keys(tools), ["list_deals"]);
  assert.equal(await tools.list_deals!.execute!({ tenant: "dach" }), "deals dach");
  await assert.rejects(Promise.resolve(tools.list_deals!.execute!({ tenant: "enterprise" })), ScopeDeniedError);
});

test("effective scopes", () => {
  assert.deepEqual(scope.effectiveScopes(hanna), ["docs:hr", "hr:read"]);
});
