import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOidcRp, OIDC_TX_COOKIE, OidcError } from '../dist/oidc-rp/index.js';

const config = {
  issuer: 'https://id.tessera.at',
  clientId: 'tsr_test',
  clientSecret: 'shhh',
  redirectUri: 'https://app.example/oauth/callback',
  sessionSecret: 'test-secret',
};

test('exports the tx cookie name', () => {
  assert.equal(OIDC_TX_COOKIE, 'oidc_tx');
});

test('tx cookie round-trips', () => {
  const rp = createOidcRp(config);
  const cookie = rp.createTxCookie({ state: 's1', nonce: 'n1', verifier: 'v1' });
  const tx = rp.readTxCookie(cookie);
  assert.ok(tx);
  assert.equal(tx.state, 's1');
  assert.equal(tx.nonce, 'n1');
  assert.equal(tx.verifier, 'v1');
  assert.ok(tx.exp > Date.now());
});

test('tx cookie rejects a tampered signature', () => {
  const rp = createOidcRp(config);
  const cookie = rp.createTxCookie({ state: 's1', nonce: 'n1', verifier: 'v1' });
  const [payload] = cookie.split('.');
  assert.equal(rp.readTxCookie(`${payload}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`), null);
});

test('tx cookie rejects a foreign session secret', () => {
  const rp = createOidcRp(config);
  const other = createOidcRp({ ...config, sessionSecret: 'other-secret' });
  const cookie = rp.createTxCookie({ state: 's1', nonce: 'n1', verifier: 'v1' });
  assert.equal(other.readTxCookie(cookie), null);
});

test('buildAuthTransaction produces a PKCE authorize URL on the issuer', () => {
  const rp = createOidcRp(config);
  const { url, cookie } = rp.buildAuthTransaction('did:plc:abc');
  const u = new URL(url);
  assert.equal(u.origin, 'https://id.tessera.at');
  assert.equal(u.pathname, '/auth');
  assert.equal(u.searchParams.get('client_id'), 'tsr_test');
  assert.equal(u.searchParams.get('redirect_uri'), config.redirectUri);
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('login_hint'), 'did:plc:abc');
  const tx = rp.readTxCookie(cookie);
  assert.ok(tx);
  assert.equal(u.searchParams.get('state'), tx.state);
  assert.equal(u.searchParams.get('nonce'), tx.nonce);
});

test('completeAuthTransaction rejects a state mismatch before any network call', async () => {
  const rp = createOidcRp(config);
  const { cookie } = rp.buildAuthTransaction();
  await assert.rejects(
    rp.completeAuthTransaction(new URLSearchParams({ state: 'wrong', code: 'c' }), cookie),
    OidcError,
  );
});

test('completeAuthTransaction rejects a missing tx cookie', async () => {
  const rp = createOidcRp(config);
  await assert.rejects(
    rp.completeAuthTransaction(new URLSearchParams({ state: 's', code: 'c' }), undefined),
    OidcError,
  );
});

const scopeOf = (rp: ReturnType<typeof createOidcRp>) =>
  new URL(rp.buildAuthTransaction().url).searchParams.get('scope');

test('buildAuthTransaction defaults to openid only', () => {
  assert.equal(scopeOf(createOidcRp(config)), 'openid');
});

test('buildAuthTransaction passes configured scopes and keeps openid first', () => {
  assert.equal(scopeOf(createOidcRp({ ...config, scopes: ['openid', 'orgs'] })), 'openid orgs');
});

test('buildAuthTransaction injects openid when the caller omits it', () => {
  const scope = scopeOf(createOidcRp({ ...config, scopes: ['orgs'] }));
  assert.ok(scope?.split(' ').includes('openid'), `expected openid in "${scope}"`);
});

test('buildAuthTransaction ignores an empty scopes array (defaults to openid)', () => {
  assert.equal(scopeOf(createOidcRp({ ...config, scopes: [] })), 'openid');
});

test('buildEndSessionUrl points at the issuer end_session endpoint with client_id', () => {
  const rp = createOidcRp(config);
  const url = new URL(rp.buildEndSessionUrl());
  assert.equal(url.origin + url.pathname, 'https://id.tessera.at/session/end');
  assert.equal(url.searchParams.get('client_id'), config.clientId);
});

test('buildEndSessionUrl carries post_logout_redirect_uri and state when given', () => {
  const rp = createOidcRp(config);
  const url = new URL(
    rp.buildEndSessionUrl({ postLogoutRedirectUri: 'https://app.example/', state: 'st1' }),
  );
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.example/');
  assert.equal(url.searchParams.get('state'), 'st1');
});

test('buildEndSessionUrl defaults the return target to the redirectUri origin', () => {
  // Every RP registers a redirect URI; its origin is a target the app already
  // controls, so "logout returns you home" needs zero extra configuration.
  const rp = createOidcRp(config);
  const url = new URL(rp.buildEndSessionUrl());
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.example');
});

test('buildEndSessionUrl lets an explicit return target win over the default', () => {
  const rp = createOidcRp(config);
  const url = new URL(rp.buildEndSessionUrl({ postLogoutRedirectUri: 'https://app.example/bye' }));
  assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.example/bye');
});

// Every cause used to collapse into one message, which made a live incident
// undiagnosable: "missing or expired" cannot tell a cookie the browser never
// sent from one signed with the wrong secret.
test('completeAuthTransaction reports WHY the tx cookie was unusable', async () => {
  const rp = createOidcRp(config);
  const params = new URLSearchParams({ state: 's', code: 'c' });
  const reasonOf = async (cookie: string | undefined) => {
    try {
      await rp.completeAuthTransaction(params, cookie);
      return 'no-error';
    } catch (err) {
      assert.ok(err instanceof OidcError);
      return (err as OidcError & { reason?: string }).reason;
    }
  };

  assert.equal(await reasonOf(undefined), 'absent');
  assert.equal(await reasonOf(''), 'absent');
  assert.equal(await reasonOf('not-a-cookie'), 'malformed');

  const good = rp.createTxCookie({ state: 's1', nonce: 'n1', verifier: 'v1' });
  const [payload] = good.split('.');
  assert.equal(await reasonOf(`${payload}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`), 'bad-signature');

  // Foreign secret = same shape, different signature.
  const other = createOidcRp({ ...config, sessionSecret: 'other-secret' });
  assert.equal(await reasonOf(other.createTxCookie({ state: 's', nonce: 'n', verifier: 'v' })), 'bad-signature');
});

// `expired` and `incomplete` are the two reasons a live incident is most likely
// to show, so they must be distinguishable too. Forging them means re-signing a
// payload the way the SDK does (HMAC-SHA256 over the raw JSON, base64url).
test('completeAuthTransaction distinguishes expired from incomplete', async () => {
  const { createHmac } = await import('node:crypto');
  const forge = (payloadObj: unknown) => {
    // The SDK signs the base64url payload, not the raw JSON (createTxCookie).
    const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
    const sig = createHmac('sha256', config.sessionSecret).update(payload).digest('base64url');
    return `${payload}.${sig}`;
  };
  const rp = createOidcRp(config);
  const params = new URLSearchParams({ state: 's', code: 'c' });
  const reasonOf = async (cookie: string) => {
    try {
      await rp.completeAuthTransaction(params, cookie);
      return 'no-error';
    } catch (err) {
      return (err as OidcError & { reason?: string }).reason;
    }
  };

  assert.equal(
    await reasonOf(forge({ state: 's', nonce: 'n', verifier: 'v', exp: Date.now() - 1000 })),
    'expired',
  );
  assert.equal(
    await reasonOf(forge({ state: 's', nonce: 'n', exp: Date.now() + 60_000 })),
    'incomplete',
  );
});

test('readTxCookie keeps its null contract while inspection reports reasons', () => {
  const rp = createOidcRp(config);
  assert.equal(rp.readTxCookie('not-a-cookie'), null);
  const tx = rp.readTxCookie(rp.createTxCookie({ state: 's', nonce: 'n', verifier: 'v' }));
  assert.equal(tx?.state, 's');
});
