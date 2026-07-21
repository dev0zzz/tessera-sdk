# tessera-sdk

Shared integration layer for apps in the [Tessera](https://tessera.at)
ecosystem — a self-hosted atproto PDS with passkey-only auth and an OIDC
bridge. One package, subpath exports, consumed as a git dependency:

```jsonc
// package.json
"dependencies": {
  "tessera-sdk": "github:dev0zzz/tessera-sdk#v0.1.0"
}
```

The `prepare` script builds `dist/` automatically on git install.

## Modules

### `tessera-sdk/core`

Isomorphic PDS helpers: handle validation/normalization
(`isTesseraHandle`, `normalizeHandle`), handle↔DID resolution
(`resolveTesseraHandle`, `resolveDidToHandle`), display helpers
(`shortenDid`). PDS URL defaults to `https://pds.tessera.at`, overridable
via `TESSERA_PDS_URL`.

### `tessera-sdk/oidc-rp`

Minimal OIDC relying-party for **identity-only** apps ("Login mit Tessera"
via `id.tessera.at`): authorization code + PKCE, `client_secret_post`,
HMAC-signed transaction cookie, ID-token claim validation. Node-only.

```ts
import { createOidcRp, OIDC_TX_COOKIE } from 'tessera-sdk/oidc-rp';

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

### `tessera-sdk/auth-browser`

Direct atproto OAuth for **browser** apps that read/write the user's repo
(peer deps: `@atproto/api`, `@atproto/oauth-client-browser`). Loopback dev
mode included; production uses a hosted `client-metadata.json`.

```ts
import { createBrowserAuth } from 'tessera-sdk/auth-browser';
const auth = createBrowserAuth({ clientId: 'https://app.tessera.at/client-metadata.json' });
const state = await auth.initAuth();       // session restore / callback
await auth.signIn('login');                // straight to the passkey dialog
const agent = auth.getAgent();             // authed Agent for repo writes
```

### `tessera-sdk/auth-node`

Direct atproto OAuth for **server-side** apps (peer deps:
`@atproto/oauth-client-node`, `better-sqlite3`): SQLite state/session
stores on a persistent volume, in-process refresh lock, and
`createTesseraNodeClient({ appUrl, clientName, dbPath })` for the standard
Tessera client shape. Composable pieces (`openOAuthDb`,
`createSqliteStores`, `requestLock`) are exported individually.

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
