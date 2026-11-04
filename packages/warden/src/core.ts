import * as wasm from "../wasm/warden_wasm";

export type Effect = "allow" | "require_approval" | "deny";
export type AttrValue = string | number | boolean | string[];

export interface Subject {
  id: string;
  kind?: "user" | "service";
  roles?: string[];
  attrs?: Record<string, AttrValue>;
}

/** A verified identity: subject + acting agent + delegation chain (oldest first). */
export interface Principal {
  subject: Subject;
  agent: string;
  act?: string[];
  token_scopes?: string[] | null;
  expires_at?: number | null;
  issuer?: string | null;
}

export interface Action {
  kind: string;
  name: string;
  args?: unknown;
  /** Raw JSON for the arguments; parsed strictly by the engine (duplicate keys are denied). */
  argsRaw?: string;
  definition_hash?: string;
}

export interface Context {
  kill_switch?: "off" | "writes" | "all";
  values?: Record<string, AttrValue>;
}

export interface TraceStep {
  step: string;
  outcome: string;
  detail?: string;
}

export interface Decision {
  effect: Effect;
  rule: string;
  /** Internal reason, for logs and audit. Do not show it to the model. */
  reason: string;
  /** What the model may see. */
  model_message: string;
  trace: TraceStep[];
  policy_version: string;
}

export interface Finding {
  level: "error" | "warning";
  code: string;
  message: string;
}

export interface ScopeOptions {
  policyYaml: string;
  catalogYaml: string;
  lockJson?: string;
}

function actionJson(a: Action): string {
  const { argsRaw, ...rest } = a;
  if (argsRaw === undefined) return JSON.stringify(rest);
  const head = JSON.stringify({ ...rest, args: null });
  // Splice the raw arguments in so the engine sees exactly what the caller sent.
  return head.replace(/"args":null/, `"args":${argsRaw}`);
}

function failClosed(version: string, reason: string): Decision {
  return {
    effect: "deny",
    rule: "internal.error",
    reason,
    model_message: "This action is not permitted.",
    trace: [],
    policy_version: version,
  };
}

/** A loaded, linted policy. Construction throws if the policy has lint errors. */
export class Scope {
  private inner: wasm.Scope;

  constructor(private readonly opts: ScopeOptions) {
    this.inner = new wasm.Scope(opts.policyYaml, opts.catalogYaml, opts.lockJson);
  }

  get version(): string {
    return this.inner.version();
  }

  get warnings(): Finding[] {
    return JSON.parse(this.inner.warnings()) as Finding[];
  }

  /** Decide. Never throws for a well-formed principal; engine faults become `deny`. */
  check(principal: Principal, action: Action, context?: Context): Decision {
    try {
      const out = this.inner.check(JSON.stringify(principal), actionJson(action), context ? JSON.stringify(context) : undefined);
      return JSON.parse(out) as Decision;
    } catch (e) {
      return this.recover(e);
    }
  }

  /** Should this action be listed to the model? */
  visible(principal: Principal, action: Action, context?: Context): boolean {
    try {
      return this.inner.visible(JSON.stringify(principal), actionJson(action), context ? JSON.stringify(context) : undefined);
    } catch (e) {
      this.recover(e);
      return false;
    }
  }

  filter(principal: Principal, kind: string, names: string[], context?: Context): string[] {
    return names.filter((name) => this.visible(principal, { kind, name }, context));
  }

  effectiveScopes(principal: Principal): string[] {
    return JSON.parse(this.inner.effectiveScopes(JSON.stringify(principal))) as string[];
  }

  private recover(e: unknown): Decision {
    // A trap (panic) leaves the WASM instance unusable: rebuild it and fail closed.
    if (e instanceof Error && e.name === "RuntimeError") {
      this.inner = new wasm.Scope(this.opts.policyYaml, this.opts.catalogYaml, this.opts.lockJson);
      return failClosed(this.version, `engine trap: ${e.message}`);
    }
    return failClosed(this.version, e instanceof Error ? e.message : String(e));
  }
}

export function createScope(opts: ScopeOptions): Scope {
  return new Scope(opts);
}

export function lint(policyYaml: string, catalogYaml: string): Finding[] {
  return JSON.parse(wasm.lint(policyYaml, catalogYaml)) as Finding[];
}

/** Thrown by guarded functions. `message` is safe to show to the model. */
export class ScopeDeniedError extends Error {
  constructor(readonly decision: Decision) {
    super(decision.model_message || "This action is not permitted.");
    this.name = "ScopeDeniedError";
  }
}

export interface ApprovalRequest {
  principal: Principal;
  action: Action;
  decision: Decision;
}

export interface ApprovalAnswer {
  approved: boolean;
  approver: string;
  reason?: string;
}

/** Ask a human. Approvals are never cached: every call asks again. */
export type Approver = (req: ApprovalRequest) => Promise<ApprovalAnswer>;

export interface GuardOptions {
  kind?: string;
  approver?: Approver;
  context?: () => Context;
  onDecision?: (d: Decision, a: Action) => void;
}

function deepFreeze<T>(v: T): T {
  if (v && typeof v === "object") {
    Object.values(v as Record<string, unknown>).forEach(deepFreeze);
    Object.freeze(v);
  }
  return v;
}

/**
 * Wrap any async function as an authorized action. The wrapped function receives a frozen
 * copy of exactly the arguments that were checked (and approved).
 */
export function guard<A, R>(
  scope: Scope,
  principal: () => Principal | Promise<Principal>,
  name: string,
  fn: (args: A) => R | Promise<R>,
  opts: GuardOptions = {},
): (args: A) => Promise<R> {
  const kind = opts.kind ?? "tool";
  return async (args: A) => {
    const p = await principal();
    const checked = deepFreeze(structuredClone(args));
    const action: Action = { kind, name, args: checked };
    const ctx = opts.context?.();
    const d = scope.check(p, action, ctx);
    opts.onDecision?.(d, action);
    if (d.effect === "deny") throw new ScopeDeniedError(d);
    if (d.effect === "require_approval") {
      if (!opts.approver) throw new ScopeDeniedError({ ...d, effect: "deny", model_message: "This action requires approval and no approver is configured." });
      let answer: ApprovalAnswer;
      try {
        answer = await opts.approver({ principal: p, action, decision: d });
      } catch {
        throw new ScopeDeniedError({ ...d, effect: "deny", model_message: "This action was not approved." });
      }
      if (!answer.approved || !answer.approver || answer.approver === p.subject.id) {
        throw new ScopeDeniedError({ ...d, effect: "deny", model_message: "This action was not approved." });
      }
      const again = scope.check(p, action, opts.context?.());
      if (again.effect === "deny" || again.policy_version !== d.policy_version) {
        throw new ScopeDeniedError({ ...again, effect: "deny" });
      }
    }
    return fn(checked);
  };
}
