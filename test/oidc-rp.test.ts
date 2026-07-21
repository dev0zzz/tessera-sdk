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
