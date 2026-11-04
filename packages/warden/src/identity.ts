/**
 * Token verification for TypeScript. `jose` checks only the signature; issuer, audience,
 * expiry, token type, delegation chain and claim mapping run in the shared Rust core (WASM),
 * so Rust and TypeScript accept and reject exactly the same tokens.
 */
import { compactVerify, createRemoteJWKSet, decodeJwt, type JWTVerifyGetKey } from "jose";
import * as wasm from "../wasm/warden_wasm";
import type { Principal } from "./core";

export class TokenError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "TokenError";
  }
}

export interface VerifyOptions {
  /** identity.yaml contents (same file the gateway uses). */
  identityYaml: string;
  /** Key sets per issuer; otherwise fetched via `jwks_uri` or OIDC discovery. */
  jwks?: Record<string, JWTVerifyGetKey>;
  /** Unix seconds; defaults to the current time. */
  now?: () => number;
}

interface IssuerInfo {
  issuer: string;
  audience: string;
  algorithms: string[];
  jwks_uri?: string | null;
}

export class TokenVerifier {
  private readonly issuers: IssuerInfo[];
  private readonly keys = new Map<string, JWTVerifyGetKey>();

  constructor(private readonly opts: VerifyOptions) {
    this.issuers = JSON.parse(wasm.identityIssuers(opts.identityYaml)) as IssuerInfo[];
    for (const [iss, k] of Object.entries(opts.jwks ?? {})) this.keys.set(iss, k);
  }

  private async keyFor(ic: IssuerInfo): Promise<JWTVerifyGetKey> {
    const cached = this.keys.get(ic.issuer);
    if (cached) return cached;
    let uri = ic.jwks_uri ?? undefined;
    if (!uri) {
      const res = await fetch(`${ic.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
      if (!res.ok) throw new TokenError("invalid", `discovery failed: HTTP ${res.status}`);
      uri = ((await res.json()) as { jwks_uri?: string }).jwks_uri;
      if (!uri) throw new TokenError("invalid", "discovery document has no jwks_uri");
    }
    const set = createRemoteJWKSet(new URL(uri), { cooldownDuration: 60_000 });
    this.keys.set(ic.issuer, set);
    return set;
  }

  async verify(token: string): Promise<Principal> {
    let iss: string | undefined;
    try {
      iss = decodeJwt(token).iss;
    } catch {
      throw new TokenError("invalid", "not a JWT");
    }
    const ic = this.issuers.find((i) => i.issuer === iss);
    if (!ic) throw new TokenError("unknown_issuer", `token issuer \`${iss}\` is not trusted`);
    let payload: Uint8Array;
    try {
      const key = (await this.keyFor(ic)) as unknown as Parameters<typeof compactVerify>[1];
      ({ payload } = await compactVerify(token, key, { algorithms: ic.algorithms }));
    } catch (e) {
      throw new TokenError("invalid", `signature or format invalid: ${(e as Error).message}`);
    }
    const now = this.opts.now ? this.opts.now() : Math.floor(Date.now() / 1000);
    const out = JSON.parse(wasm.principalFromClaims(this.opts.identityYaml, new TextDecoder().decode(payload), now)) as
      | { ok: Principal }
      | { error: { code: string; message: string } };
    if ("error" in out) throw new TokenError(out.error.code, out.error.message);
    return out.ok;
  }
}

export async function verifyToken(token: string, opts: VerifyOptions): Promise<Principal> {
  return new TokenVerifier(opts).verify(token);
}

/** Map already-verified claims (e.g. from your own JWT library) to a principal. */
export function principalFromClaims(identityYaml: string, claims: unknown, now: number): Principal {
  const out = JSON.parse(wasm.principalFromClaims(identityYaml, JSON.stringify(claims), now)) as
    | { ok: Principal }
    | { error: { code: string; message: string } };
  if ("error" in out) throw new TokenError(out.error.code, out.error.message);
  return out.ok;
}
