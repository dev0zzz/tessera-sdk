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
});

test("tampered issuer signature -> bad_signature", async () => {
  const v = createEudiVerifier({ trustAnchors: anchors, expectedAudience: EXPECTED_AUDIENCE, now: () => AT });
  await assert.rejects(v.verifyPresentation(tampered, EXPECTED_NONCE), (e) => e instanceof EudiVerificationError && e.code === "bad_signature");
});
