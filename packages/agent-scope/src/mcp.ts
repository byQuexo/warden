/**
 * Protect your own MCP server (e.g. built with `@modelcontextprotocol/sdk`) without a gateway.
 *
 * ```ts
 * const scoped = withScope({ listTools, callTool }, scope, { principal: (extra) => verifier.verify(extra.authInfo.token) });
 * server.setRequestHandler(ListToolsRequestSchema, async (_req, extra) => ({ tools: await scoped.listTools(extra) }));
 * server.setRequestHandler(CallToolRequestSchema, async (req, extra) => scoped.callTool(req.params.name, req.params.arguments ?? {}, extra));
 * ```
 */
import type { Approver, Context, Principal, Scope } from "./core";

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface ToolResult {
  content: { type: string; text?: string; [k: string]: unknown }[];
  isError?: boolean;
  [k: string]: unknown;
}

export interface ToolHandlers<X> {
  listTools(extra?: X): ToolDef[] | Promise<ToolDef[]>;
  callTool(name: string, args: Record<string, unknown>, extra?: X): ToolResult | Promise<ToolResult>;
}

export interface WithScopeOptions<X> {
  /** Resolve the verified principal of the current request. */
  principal: (extra?: X) => Principal | Promise<Principal>;
  approver?: Approver;
  context?: () => Context;
  /** Prefix for catalog names, e.g. `"crm."` when the catalog uses namespaced names. */
  prefix?: string;
}

const denied = (text: string): ToolResult => ({ content: [{ type: "text", text }], isError: true });

export function withScope<X>(handlers: ToolHandlers<X>, scope: Scope, opts: WithScopeOptions<X>) {
  const prefix = opts.prefix ?? "";
  return {
    async listTools(extra?: X): Promise<ToolDef[]> {
      const p = await opts.principal(extra);
      const ctx = opts.context?.();
      const tools = await handlers.listTools(extra);
      return tools.filter((t) => scope.visible(p, { kind: "tool", name: prefix + t.name }, ctx));
    },
    async callTool(name: string, args: Record<string, unknown>, extra?: X): Promise<ToolResult> {
      const p = await opts.principal(extra);
      const action = { kind: "tool", name: prefix + name, args };
      const d = scope.check(p, action, opts.context?.());
      if (d.effect === "deny") return denied(d.model_message);
      if (d.effect === "require_approval") {
        const a = opts.approver ? await opts.approver({ principal: p, action, decision: d }).catch(() => null) : null;
        if (!a || !a.approved || !a.approver || a.approver === p.subject.id) return denied("This action was not approved.");
        const again = scope.check(p, action, opts.context?.());
        if (again.effect === "deny") return denied(again.model_message);
      }
      return handlers.callTool(name, structuredClone(args), extra);
    },
  };
}
