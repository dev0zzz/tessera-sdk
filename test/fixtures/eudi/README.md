# EUDI SD-JWT VC test fixtures

## Provenance

The vectors in this directory are **not** taken from the IETF SD-JWT VC test
vectors or from the EU reference issuer (`issuer.eudiw.dev`). Obtaining a real
EU-issued PID requires a live wallet interaction against the EU reference
issuer/verifier and cannot be automated in this environment. Instead, the
vectors are **self-generated deterministically**, using real SD-JWT VC
cryptography end to end (EC P-256 keys, ES256 signatures, SHA-256 disclosure
hashing) — fully offline and reproducible.

- Library: `@sd-jwt/sd-jwt-vc@0.20.0` (built on `@sd-jwt/core@0.20.0`)
- Generation script: `scratch-verify.mjs` at the repo root (uncommitted, throwaway).
  Re-running it regenerates byte-identical fixtures given the same Node crypto
  RNG output is not required to match — only the deterministic *claims* below
  are pinned; keys are freshly generated per run, so re-running changes the
  fixture bytes but not their shape or semantics.
- Signing: Node's built-in `crypto.sign`/`crypto.verify` with
  `dsaEncoding: 'ieee-p1363'` (raw JWS-compatible signature format, not DER).
- Hasher: `crypto.createHash('sha256')`, wired in as the library's `hasher`
  config with `hashAlg: 'sha-256'`.

### valid-presentation.txt

A compact `<issuer-signed JWT>~<disclosure>~<KB-JWT>` string.

- Issuer: `https://issuer.example/eudi`
- `vct`: `https://issuer.example/eudi/pid`
- Claims issued (disclosure frame `_sd: ['age_over_18', 'given_name', 'birthdate']`):
  `age_over_18: true`, `given_name: "Erika"`, `birthdate: "1990-01-01"`
- Claims kept plain (not selectively disclosed): `iss`, `vct`, `iat`, `nbf`,
  `exp`, `cnf.jwk` (holder's P-256 public key)
- Presentation frame discloses only `age_over_18` (one disclosure segment).
- Key-Binding JWT is signed by the holder key referenced in `cnf.jwk` and
  binds to the constants below.

**Constants (fixed, reproducible — used by Task 6's integration test):**

| Constant | Value |
|---|---|
| `iss` | `https://issuer.example/eudi` |
| `vct` | `https://issuer.example/eudi/pid` |
| KB `aud` | `https://verifier.example/eudi/rp` |
| KB `nonce` | `n-0S6_WzA2Mj` |
| `nbf` (epoch seconds) | `1749996400` |
| `exp` (epoch seconds) | `1781536000` |
| `iat` / KB `iat` (epoch seconds) | `1750000000` |
| valid `now` inside window (epoch seconds) | `1750000000` |

### trust-anchors.json

The issuer's EC P-256 public key as JWK, in the shape:

```json
[
  { "issuer": "https://issuer.example/eudi", "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } }
]
```

Note this is the **issuer's** key, distinct from `cnf.jwk` inside the
presentation payload, which is the **holder's** key (used only for Key-Binding
JWT verification).

### tampered-signature.txt

Byte-identical to `valid-presentation.txt` except one character is flipped in
the signature segment of the first (issuer-signed) `~`-separated token — i.e.
the part after the second `.` of `<issuer-JWT>`. The KB-JWT and disclosure are
untouched. The vector still parses structurally (three dot-separated JWT
segments, correct `~` framing) but fails signature verification.

## Library API contract (implemented by `src/eudi/sdjwt.ts` in Task 6)

Both functions below come from `@sd-jwt/sd-jwt-vc@0.20.0`'s `SDJwtVcInstance`
(re-exported, extends `@sd-jwt/core@0.20.0`'s `SDJwtInstance`).

### (a) Verify the issuer signature with a supplied key

```ts
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';

const sdjwt = new SDJwtVcInstance({
  hasher: (data: string, alg: string) => Uint8Array,       // e.g. sha-256 -> crypto.createHash('sha256')
  hashAlg: 'sha-256',
  verifier: (data: string, sig: string, options?) => boolean | Promise<boolean>, // checks issuer signature against the trust-anchor JWK
  kbVerifier: (data: string, sig: string, payload: SdJwtVcPayload) => boolean | Promise<boolean>, // checks KB-JWT signature against payload.cnf.jwk
});

const result = await sdjwt.verify(compactPresentation, {
  currentDate: number,      // epoch seconds; defaults to Date.now()/1000 if omitted
  keyBindingNonce: string,  // REQUIRED to trigger KB-JWT verification at all — if omitted, verify() returns without checking KB
});
// result: { payload: SdJwtVcPayload, header, kb?: { payload: kbPayload, header: kbHeader } }
```

Key points learned from `@sd-jwt/core`'s implementation
(`node_modules/@sd-jwt/core/dist/index.mjs`):

- `verifier` and `kbVerifier` are supplied once at **construction** time (via
  `SDJWTConfig`), not per-call. They must be closures over the correct trust
  anchor / holder key — the caller (Task 6) is responsible for resolving the
  issuer JWK from `trust-anchors.json` by `iss` and building the `verifier`
  closure before calling `verify()`.
- `verify()` only checks the Key-Binding JWT if `options.keyBindingNonce` is
  passed. It checks `kb.payload.nonce === options.keyBindingNonce` internally,
  but does **not** check `kb.payload.aud` against anything automatically —
  the caller must compare `result.kb.payload.aud` to the expected RP
  `client_id`/`aud` themselves after `verify()` returns.
- `nbf`/`exp`/`iat` on the issuer-signed payload are checked automatically
  against `options.currentDate` (default: wall-clock now) with optional
  `options.skewSeconds`.
- On signature failure, `verify()` throws (`SDJWTException` /
  `Error: signature is not valid`); it does not return a falsy result. Use
  `safeVerify()` (same signature, wraps in `{ success, errors }` /
  `{ success, payload, ... }`) if fail-fast is undesirable.

### (b) Read the KB-JWT `aud`/`nonce`

They come back directly on the `verify()`/`safeVerify()` result, already
decoded — no separate call is needed:

```ts
result.kb.payload.aud    // string
result.kb.payload.nonce  // string
result.kb.payload.iat    // number (epoch seconds)
result.kb.payload.sd_hash // string — library-computed, already validated against the presented disclosures
result.kb.header.alg     // string, e.g. "ES256"
result.kb.header.typ     // "kb+jwt"
```

If Key-Binding JWT decoding without full verification is ever needed
independently, `@sd-jwt/core` exposes `KBJwt.fromKBEncode(encodedJwt)` →
`{ header, payload, signature }`, but Task 6's flow does not need this since
`verify()` already returns the decoded, signature-checked KB payload.
