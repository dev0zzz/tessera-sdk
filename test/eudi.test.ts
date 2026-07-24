import { test } from "node:test";
import assert from "node:assert/strict";
import { EudiVerificationError, createEudiVerifier } from "../dist/eudi/index.js";

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
