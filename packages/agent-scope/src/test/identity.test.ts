import { test } from "node:test";
import assert from "node:assert/strict";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { TokenError, TokenVerifier } from "../identity";

const ISS = "https://idp.test";
const AUD = "https://gw.test/mcp";
const identityYaml = `version: 1
issuers:
  - issuer: ${ISS}
    audience: ${AUD}
    algorithms: [ES256]
    mapping: { preset: keycloak, attrs: { tenants: /tenants } }
`;

async function setup() {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256" };
  const now = Math.floor(Date.now() / 1000);
  const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = {}) =>
    new SignJWT({ typ: "Bearer", azp: "acme-bot", realm_access: { roles: ["sales-rep"] }, scope: "crm:read", tenants: ["dach"], exp: now + 60, ...claims })
      .setProtectedHeader({ alg: "ES256", kid: "k1", ...header })
      .setIssuer(ISS)
      .setAudience(AUD)
      .setSubject("sven")
      .sign(privateKey);
  const verifier = new TokenVerifier({ identityYaml, jwks: { [ISS]: createLocalJWKSet({ keys: [jwk] }) } });
  return { sign, verifier, now };
}

test("verifies signature with jose and maps claims with the shared core", async () => {
  const { sign, verifier } = await setup();
  const p = await verifier.verify(await sign({}));
  assert.equal(p.subject.id, "sven");
  assert.equal(p.agent, "acme-bot");
  assert.deepEqual(p.subject.roles, ["sales-rep"]);
  assert.deepEqual(p.subject.attrs?.tenants, ["dach"]);
});

test("rejects tampered, unsigned, expired and foreign tokens", async () => {
  const { sign, verifier, now } = await setup();
  const good = await sign({});
  const [h, , s] = good.split(".");
  const evil = Buffer.from(JSON.stringify({ iss: ISS, aud: AUD, sub: "sven", azp: "acme-bot", typ: "Bearer", exp: now + 60, realm_access: { roles: ["admin"] } })).toString("base64url");
  await assert.rejects(verifier.verify(`${h}.${evil}.${s}`), (e: unknown) => e instanceof TokenError && e.code === "invalid");

  const none = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${evil}.`;
  await assert.rejects(verifier.verify(none), (e: unknown) => e instanceof TokenError && e.code === "invalid");

  await assert.rejects(verifier.verify(await sign({ exp: now - 3600 })), (e: unknown) => e instanceof TokenError && e.code === "expired");
  await assert.rejects(verifier.verify(await sign({ typ: "ID" })), (e: unknown) => e instanceof TokenError && e.code === "token_type");
  await assert.rejects(verifier.verify(await new SignJWT({}).setProtectedHeader({ alg: "ES256" }).setIssuer("https://other").sign((await generateKeyPair("ES256")).privateKey)), (e: unknown) => e instanceof TokenError && e.code === "unknown_issuer");
});
