import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createEudiVerifier, EudiVerificationError } from "../dist/eudi/index.js";

const vp = readFileSync(new URL("./fixtures/eudi/valid-presentation.txt", import.meta.url), "utf8").trim();
const tampered = readFileSync(new URL("./fixtures/eudi/tampered-signature.txt", import.meta.url), "utf8").trim();
const anchors = JSON.parse(readFileSync(new URL("./fixtures/eudi/trust-anchors.json", import.meta.url), "utf8"));

// Constants pinned by Task 1's fixture generation — see test/fixtures/eudi/README.md.
const EXPECTED_AUDIENCE = "https://verifier.example/eudi/rp";
const EXPECTED_NONCE = "n-0S6_WzA2Mj";
const AT = 1750000000; // fixed `now` inside the vector's [nbf, exp] validity window

test("real vector verifies against its trust anchor", async () => {
  const v = createEudiVerifier({ trustAnchors: anchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  const out = await v.verifyPresentation(vp, EXPECTED_NONCE);
  assert.equal(typeof out.issuer, "string");
  assert.ok("age_over_18" in out.claims);
  // Selective-disclosure non-leakage: undisclosed claims and SD-JWT internal
  // bookkeeping keys must never appear in the claims returned to callers.
  assert.ok(!("given_name" in out.claims));
  assert.ok(!("birthdate" in out.claims));
  assert.ok(!("_sd" in out.claims));
  assert.ok(!("_sd_alg" in out.claims));
});

test("tampered issuer signature -> bad_signature", async () => {
  const v = createEudiVerifier({ trustAnchors: anchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(v.verifyPresentation(tampered, EXPECTED_NONCE), (e) => e instanceof EudiVerificationError && e.code === "bad_signature");
});

test("untrusted issuer (empty trust-anchor list) -> untrusted_issuer, via real primitive", async () => {
  const v = createEudiVerifier({ trustAnchors: [], expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(
    v.verifyPresentation(vp, EXPECTED_NONCE),
    (e) => e instanceof EudiVerificationError && e.code === "untrusted_issuer",
  );
});

test("missing key binding (KB-JWT segment stripped) -> missing_key_binding, via real primitive", async () => {
  const withoutKb = vp.slice(0, vp.lastIndexOf("~") + 1);
  const v = createEudiVerifier({ trustAnchors: anchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(
    v.verifyPresentation(withoutKb, EXPECTED_NONCE),
    (e) => e instanceof EudiVerificationError && e.code === "missing_key_binding",
  );
});

test("expired (now just past exp) -> expired, via real primitive", async () => {
  const v = createEudiVerifier({
    trustAnchors: anchors,
    expectedAudience: EXPECTED_AUDIENCE,
    now: () => 1781536001, // 1s past the fixture's exp=1781536000
  });
  await assert.rejects(
    v.verifyPresentation(vp, EXPECTED_NONCE),
    (e) => e instanceof EudiVerificationError && e.code === "expired",
  );
});

test("malformed trust-anchor key -> untrusted_issuer (not a bare TypeError)", async () => {
  const malformedAnchors = [
    {
      issuer: "https://issuer.example/eudi",
      publicKeyJwk: { kty: "EC", crv: "P-256", x: "not-valid-base64url-coords!!", y: "also-not-valid!!" },
    },
  ];
  const v = createEudiVerifier({ trustAnchors: malformedAnchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(
    v.verifyPresentation(vp, EXPECTED_NONCE),
    (e) => e instanceof EudiVerificationError && e.code === "untrusted_issuer",
  );
});

test("wrong expected nonce -> nonce_mismatch, via real primitive", async () => {
  const v = createEudiVerifier({ trustAnchors: anchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(
    v.verifyPresentation(vp, "wrong-nonce"),
    (e) => e instanceof EudiVerificationError && e.code === "nonce_mismatch",
  );
});
