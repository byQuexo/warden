/**
 * Vercel AI SDK (or any `{ name: { execute } }` tool map): hide tools the principal may not
 * use and check every execution.
 *
 * ```ts
 * const tools = scopeTools(scope, principal, { list_deals: tool({...}), update_deal: tool({...}) }, { prefix: "crm." });
 * await generateText({ model, tools, prompt });
 * ```
 */
import { guard, type Approver, type Context, type Principal, type Scope } from "./core";

type Executable = { execute?: (args: any, options?: any) => unknown; [k: string]: unknown };

export interface ScopeToolsOptions {
  prefix?: string;
  approver?: Approver;
  context?: () => Context;
}

export function scopeTools<T extends Record<string, Executable>>(scope: Scope, principal: Principal, tools: T, opts: ScopeToolsOptions = {}): Partial<T> {
  const prefix = opts.prefix ?? "";
  const out: Partial<T> = {};
  for (const [name, tool] of Object.entries(tools) as [keyof T & string, Executable][]) {
    const full = prefix + name;
    if (!scope.visible(principal, { kind: "tool", name: full }, opts.context?.())) continue;
    const execute = tool.execute;
    out[name] = {
      ...tool,
      execute: execute
        ? (args: unknown, options?: unknown) =>
            guard(scope, () => principal, full, (checked: unknown) => execute(checked, options), { approver: opts.approver, context: opts.context })(args)
        : undefined,
    } as unknown as T[typeof name];
  }
  return out;
}
