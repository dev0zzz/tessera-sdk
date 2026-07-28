# @tesseraat/sdk

Shared integration layer for apps in the [Tessera](https://tessera.at)
ecosystem — a self-hosted atproto PDS with passkey-only auth and an OIDC
bridge. One package, subpath exports:

```sh
npm install @tesseraat/sdk
```

Published to npm rather than consumed as a git dependency, and that difference is
not cosmetic. A git dependency carries no `dist/` — the repository ignores it — so
`prepare` ran a full TypeScript build **on every consumer's machine**, needing this
package's devDependencies, network access and an SSH key, and failing the
consumer's install whenever any of it was missing. A published tarball ships
`dist/` prebuilt: installing is a download.

It also restores what a version range is for. Three apps pinned tags —
`tessera-web` and `tessera-oidc` at v0.7.0, `ledger` at v0.5.0 — while this package
was already at v0.8.0. A tag is not a range, so nothing had any reason to tell them
so; it took reading three package.json files side by side to notice.

Releases run from a tag push via `.github/workflows/publish.yml`, authenticated by
OIDC ("trusted publishing"). There is no `NPM_TOKEN` anywhere: npm verifies with
GitHub that the workflow is genuine, so no long-lived secret exists to leak — and
npm is restricting 2FA-bypassing tokens regardless (account changes Aug 2026,
direct publishing Jan 2027). Each published version carries a provenance statement
tying it to the commit it was built from.

## Modules

### `@tesseraat/sdk/core`

Isomorphic PDS helpers: handle validation/normalization
(`isTesseraHandle`, `normalizeHandle`), handle↔DID resolution
(`resolveTesseraHandle`, `resolveDidToHandle`), display helpers
(`shortenDid`). PDS URL defaults to `https://pds.tessera.at`, overridable
via `TESSERA_PDS_URL`.

### `@tesseraat/sdk/oidc-rp`

Minimal OIDC relying-party for **identity-only** apps ("Login mit Tessera"
via `id.tessera.at`): authorization code + PKCE, `client_secret_post`,
HMAC-signed transaction cookie, ID-token claim validation. Node-only.

```ts
import { createOidcRp, OIDC_TX_COOKIE } from '@tesseraat/sdk/oidc-rp';

const rp = createOidcRp({
  issuer: 'https://id.tessera.at',
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: `${publicUrl}/oauth/callback`,
  sessionSecret: process.env.SESSION_SECRET!,
});

// login route:
const { url, cookie } = rp.buildAuthTransaction(optionalDidLoginHint);
// set OIDC_TX_COOKIE=cookie (HttpOnly, Secure, Lax, short-lived), redirect to url

// callback route:
const did = await rp.completeAuthTransaction(url.searchParams, txCookieValue);
```

### `@tesseraat/sdk/eudi`

Verify a state-signed EUDI presentation (SD-JWT VC over OpenID4VP) against
an EU trust list and return only the selectively-disclosed claims. Pure,
stateless, Node-only. **Fetching/refreshing the trust list is the caller's
responsibility** — this module only checks a presentation against the
`trustAnchors` it's handed; it never fetches or caches anything itself.

```ts
import { createEudiVerifier, EudiVerificationError } from '@tesseraat/sdk/eudi';

const verifier = createEudiVerifier({
  trustAnchors: [{ issuer: 'https://issuer.example', publicKeyJwk }],
  expectedAudience: 'https://relying-party.example',
});

try {
  const { issuer, claims, verifiedAt } = await verifier.verifyPresentation(
    vpToken,
    expectedNonce,
  );
} catch (err) {
  if (err instanceof EudiVerificationError) {
    // err.code: 'malformed' | 'untrusted_issuer' | 'bad_signature' | 'expired'
    //         | 'not_yet_valid' | 'audience_mismatch' | 'nonce_mismatch'
    //         | 'missing_key_binding'
  }
}
```

`verifyPresentation(vpToken, expectedNonce)` checks the SD-JWT signature
against the configured trust anchors, key-binding audience/nonce, and
validity window, then returns the disclosed `claims` — never the raw
credential. `malformed` / `bad_signature` / `untrusted_issuer` /
`missing_key_binding` come from the signature/structure layer;
`audience_mismatch` / `nonce_mismatch` / `expired` / `not_yet_valid` come
from the policy layer.

### `@tesseraat/sdk/auth-browser`

Direct atproto OAuth for **browser** apps that read/write the user's repo
(peer deps: `@atproto/api`, `@atproto/oauth-client-browser`). Loopback dev
mode included; production uses a hosted `client-metadata.json`.

```ts
import { createBrowserAuth } from '@tesseraat/sdk/auth-browser';
const auth = createBrowserAuth({ clientId: 'https://app.tessera.at/client-metadata.json' });
const state = await auth.initAuth();       // session restore / callback
await auth.signIn('login');                // straight to the passkey dialog
const agent = auth.getAgent();             // authed Agent for repo writes
```

### `@tesseraat/sdk/auth-node`

Direct atproto OAuth for **server-side** apps (peer deps:
`@atproto/oauth-client-node`, `better-sqlite3`): SQLite state/session
stores on a persistent volume, in-process refresh lock, and
`createTesseraNodeClient({ appUrl, clientName, dbPath })` for the standard
Tessera client shape. Composable pieces (`openOAuthDb`,
`createSqliteStores`, `requestLock`) are exported individually.

## Lexicons

`lexicons/at/tessera/**` is the **canonical home** of every at.tessera.*
schema (record collections AND XRPC methods). The atproto fork consumes
copies at build time — after changing a schema here, run
`scripts/sync-lexicons.sh [atproto-path]` and re-run the fork's
`pnpm run codegen:lex` in `packages/pds`. The PDS validates the record
collections server-side, so clients never need `validate: false`.

## Decision rule

Apps that read/write the user's repo **as the user** use direct atproto
OAuth against the PDS instead of this bridge (planned `auth-browser` /
`auth-node` modules). Apps that only need identity (DID, handle, profile)
use `oidc-rp`.

## Development

```bash
npm ci
npm run build
npm test
```
