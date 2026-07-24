/**
 * Real cryptographic primitive for EUDI SD-JWT VC presentations, backed by
 * @sd-jwt/sd-jwt-vc. Wired as the default `CredentialVerifier` in ./index.js.
 *
 * Flow: split the compact presentation -> read (but do not yet trust) the
 * issuer -> resolve its trust-anchor key -> hand the whole presentation to
 * the library, which verifies the issuer signature, applies the disclosures,
 * and (because we always force a Key-Binding check) verifies the KB-JWT
 * against the credential's own `cnf.jwk`. Every failure mode is translated
 * into an `EudiVerificationError` with a code from the fixed union — no bare
 * Error and no library exception ever escapes this module.
 */

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";
import type { CredentialVerifier } from "./index.js";
import { EudiVerificationError } from "./index.js";

const SD_SEPARATOR = "~";

interface SplitPresentation {
  issuerJwt: string;
  kbJwt?: string;
}

/**
 * Splits a compact SD-JWT VC presentation `<issuer-jwt>~<disclosure>*~<kb-jwt>?`
 * into its issuer-signed JWT and (optional) Key-Binding JWT segment. Mirrors
 * @sd-jwt/core's internal `splitSdJwt` convention: the last `~`-segment is
 * popped off as the KB-JWT, and is `undefined` when empty (i.e. the
 * presentation string ends with a trailing "~", meaning no key binding).
 */
function splitPresentation(vpToken: string): SplitPresentation {
  const parts = vpToken.split(SD_SEPARATOR);
  const issuerJwt = parts[0];
  if (!issuerJwt || issuerJwt.split(".").length !== 3) {
    throw new Error("invalid issuer JWT segment");
  }
  if (parts.length === 1) {
    return { issuerJwt };
  }
  const last = parts[parts.length - 1];
  return { issuerJwt, kbJwt: last || undefined };
}

/** Decodes a compact JWT's payload segment without verifying its signature. */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const segments = jwt.split(".");
  if (segments.length !== 3) throw new Error("invalid JWT");
  const json = Buffer.from(segments[1], "base64url").toString("utf8");
  const payload: unknown = JSON.parse(json);
  if (typeof payload !== "object" || payload === null) {
    throw new Error("invalid JWT payload");
  }
  return payload as Record<string, unknown>;
}

function hasher(data: string | ArrayBuffer, alg: string): Uint8Array {
  const nodeAlg = alg.replace(/-/g, "");
  const input = typeof data === "string" ? data : Buffer.from(data);
  return new Uint8Array(createHash(nodeAlg).update(input).digest());
}

/** Verifies a raw (IEEE P1363 / JWS-compatible) ES256 signature against a JWK. */
function makeJwkVerifier(jwk: JsonWebKey): (data: string, sig: string) => boolean {
  const publicKey = createPublicKey({
    key: jwk as unknown as Record<string, unknown>,
    format: "jwk",
  });
  return (data: string, sig: string) => {
    try {
      return cryptoVerify(
        "sha256",
        Buffer.from(data),
        { key: publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(sig, "base64url"),
      );
    } catch {
      return false;
    }
  };
}

/** KB-JWT verifier: the signing key is the holder key carried in `cnf.jwk`. */
function kbVerifier(data: string, sig: string, payload: { cnf?: { jwk?: JsonWebKey } }): boolean {
  const jwk = payload?.cnf?.jwk;
  if (!jwk) return false;
  try {
    return makeJwkVerifier(jwk)(data, sig);
  } catch {
    return false;
  }
}

/**
 * Picks a `currentDate` (epoch seconds) that the library's internal
 * iat/nbf/exp checks are guaranteed to accept, so the *only* clock that
 * actually governs business validity is the caller's injected `now()` —
 * applied in ./index.js against the `notBefore`/`expiresAt` this primitive
 * returns. We trust nbf/exp/iat here because they are always plain
 * (non-selectively-disclosed) claims on the issuer JWT — reading them before
 * signature verification is exactly as safe as reading `iss` is.
 *
 * This "neutralize the library's internal clock, enforce our own on the
 * outside" trick relies on `@sd-jwt/core` internal semantics: `currentDate`
 * governs the library's internal nbf/exp check, and supplying
 * `keyBindingNonce` (below, in `sdjwt.verify(...)`) is what triggers KB
 * verification at all. Documented as the "Library API contract" in
 * test/fixtures/eudi/README.md. That coupling to undocumented internals is
 * why `@sd-jwt/sd-jwt-vc` is pinned to an exact version in package.json —
 * a silent patch bump must not be allowed to change this behavior underneath
 * us.
 */
function pickNeutralCurrentDate(payload: Record<string, unknown>): number {
  if (typeof payload.iat === "number") return payload.iat;
  if (typeof payload.nbf === "number") return payload.nbf;
  if (typeof payload.exp === "number") return payload.exp;
  return Math.floor(Date.now() / 1000);
}

export const defaultCredentialVerifier: CredentialVerifier = async (vpToken, resolveIssuerKey) => {
  let split: SplitPresentation;
  let issuerPayload: Record<string, unknown>;
  try {
    split = splitPresentation(vpToken);
    issuerPayload = decodeJwtPayload(split.issuerJwt);
  } catch {
    throw new EudiVerificationError("unparseable presentation", "malformed");
  }

  const iss = issuerPayload.iss;
  if (typeof iss !== "string" || iss.length === 0) {
    throw new EudiVerificationError("presentation has no issuer claim", "malformed");
  }

  const key = resolveIssuerKey(iss);
  if (!key) {
    throw new EudiVerificationError(`issuer not trusted: ${iss}`, "untrusted_issuer");
  }

  if (!split.kbJwt) {
    throw new EudiVerificationError("presentation has no key binding JWT", "missing_key_binding");
  }

  let kbNonce: string;
  try {
    const kbPayload = decodeJwtPayload(split.kbJwt);
    if (typeof kbPayload.nonce !== "string" || kbPayload.nonce.length === 0) {
      throw new Error("key binding JWT has no nonce");
    }
    kbNonce = kbPayload.nonce;
  } catch {
    throw new EudiVerificationError("unparseable key binding JWT", "malformed");
  }

  let sdjwt: SDJwtVcInstance;
  try {
    sdjwt = new SDJwtVcInstance({
      hasher,
      hashAlg: "sha-256",
      verifier: makeJwkVerifier(key),
      kbVerifier,
    });
  } catch (e) {
    // A malformed/unusable trust-anchor key means the issuer's trust cannot
    // be established — this is an operator-config problem, not a signature
    // failure, so it must NOT be mapped to "bad_signature".
    const detail = e instanceof Error ? e.message : String(e);
    throw new EudiVerificationError(`unusable trust-anchor key for issuer ${iss}: ${detail}`, "untrusted_issuer");
  }

  let result;
  try {
    // Passing `keyBindingNonce` is what makes the library verify the KB-JWT
    // at all (see @sd-jwt/core); the nonce we pass is read straight off the
    // (not-yet-verified) KB-JWT itself, so the library's internal
    // `payload.nonce === options.keyBindingNonce` check is a structural
    // no-op here — the real expected-nonce comparison happens one layer up,
    // in ./index.js, against the *returned* (now verified) keyBindingNonce.
    result = await sdjwt.verify(vpToken, {
      currentDate: pickNeutralCurrentDate(issuerPayload),
      keyBindingNonce: kbNonce,
    });
  } catch (e) {
    if (e instanceof EudiVerificationError) throw e;
    throw new EudiVerificationError("signature verification failed", "bad_signature");
  }

  if (!result.kb) {
    // Defensive: split.kbJwt was present, so the library should always have
    // verified and returned it once we forced the keyBindingNonce path.
    throw new EudiVerificationError("presentation has no key binding JWT", "missing_key_binding");
  }

  const claims = result.payload as Record<string, unknown>;
  return {
    issuer: iss,
    claims,
    notBefore: typeof claims.nbf === "number" ? claims.nbf : undefined,
    expiresAt: typeof claims.exp === "number" ? claims.exp : undefined,
    keyBindingAudience: result.kb.payload.aud,
    keyBindingNonce: result.kb.payload.nonce,
    hasKeyBinding: true,
  };
};
