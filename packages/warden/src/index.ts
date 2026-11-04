/**
 * warden for TypeScript.
 *
 * The decision engine is the Rust core compiled to WebAssembly, so a TypeScript agent gets
 * the same answers as the Rust gateway (verified by shared conformance vectors).
 */
export * from "./core";
export { verifyToken, principalFromClaims, TokenVerifier, TokenError, type VerifyOptions } from "./identity";
export { withScope, type ToolDef, type ToolHandlers, type ToolResult, type WithScopeOptions } from "./mcp";
export { scopeTools, type ScopeToolsOptions } from "./ai-sdk";
