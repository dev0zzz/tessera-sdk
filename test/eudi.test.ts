import { test } from "node:test";
import assert from "node:assert/strict";
import { EudiVerificationError, createEudiVerifier } from "../dist/eudi/index.js";
import { createEudiVerifier as mk } from "../dist/eudi/index.js";

test("EudiVerificationError carries a code", () => {
  const e = new EudiVerificationError("nope", "expired");
  assert.equal(e.code, "expired");
  assert.equal(e.name, "EudiVerificationError");
  assert.ok(e instanceof Error);
});

test("createEudiVerifier returns an object with verifyPresentation", () => {
  const v = createEudiVerifier({ trustAnchors: [], expectedAudience: "aud" });
  assert.equal(typeof v.verifyPresentation, "function");
});

const JWK = { kty: "EC", crv: "P-256", x: "x", y: "y" } as const;
const ANCHOR = { issuer: "https://issuer.example/eudi", publicKeyJwk: JWK };

function fakeVerifier(content) {
  return async (_vp, resolve) => {
    // simulate the primitive checking the issuer key exists
    if (!resolve(content.issuer)) {
      const { EudiVerificationError } = await import("../dist/eudi/index.js");
      throw new EudiVerificationError("no key", "untrusted_issuer");
    }
    return content;
  };
}

test("happy path returns disclosed claims", async () => {
  const content = {
    issuer: ANCHOR.issuer,
    claims: { age_over_18: true },
    notBefore: 1000,
    expiresAt: 2000,
    keyBindingAudience: "rp.example",
    keyBindingNonce: "n-123",
    hasKeyBinding: true,
  };
  const v = mk({
    trustAnchors: [ANCHOR],
    expectedAudience: "rp.example",
    now: () => 1500,
    verifier: fakeVerifier(content),
  });
  const out = await v.verifyPresentation("vp", "n-123");
  assert.deepEqual(out.claims, { age_over_18: true });
  assert.equal(out.issuer, ANCHOR.issuer);
  assert.equal(out.verifiedAt, 1500);
});
