import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * tessera-sdk/oidc-rp — minimal OIDC relying-party client for id.tessera.at
 * (authorization code + PKCE, client_secret_post). Extracted verbatim from
 * salzgrotte/mbdrone's byte-identical `src/lib/oidc.ts`; the app-specific
 * `getEnv()` coupling is replaced by an explicit config object.
 *
 * The transaction state (state, nonce, PKCE verifier) travels in a
 * short-lived HMAC-signed cookie; the ID token comes straight from the token
 * endpoint over TLS, so payload validation (iss/aud/exp/nonce) suffices
 * without local signature verification.
 */

export const OIDC_TX_COOKIE = 'oidc_tx';
const TX_TTL_MS = 10 * 60 * 1000;

const b64url = (buf: Buffer) => buf.toString('base64url');

function sign(payload: string, secret: string): string {
  return b64url(createHmac('sha256', secret).update(payload).digest());
}

export interface OidcRpConfig {
  /** OIDC issuer, no trailing slash — e.g. `https://id.tessera.at`. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Absolute redirect URI registered with the issuer, e.g. `${publicUrl}/oauth/callback`. */
  redirectUri: string;
  /** HMAC key for the short-lived transaction cookie. */
  sessionSecret: string;
  /** OAuth scopes to request. `openid` is always included. Default `['openid']`. */
  scopes?: string[];
}

export interface OidcTx {
  state: string;
  nonce: string;
  verifier: string;
  exp: number;
}

export class OidcError extends Error {}

export interface OidcRp {
  /** Starts a login: returns the authorize URL and the tx-cookie VALUE to set. */
  buildAuthTransaction(loginHint?: string): { url: string; cookie: string };
  /** Exchanges the callback code for an ID token and returns the verified DID (sub). */
  completeAuthTransaction(
    params: URLSearchParams,
    txCookie: string | undefined,
  ): Promise<string>;
  createTxCookie(tx: Omit<OidcTx, 'exp'>): string;
  readTxCookie(value: string): OidcTx | null;
}

export function createOidcRp(config: OidcRpConfig): OidcRp {
  const issuer = config.issuer.replace(/\/$/, '');

  function createTxCookie(tx: Omit<OidcTx, 'exp'>): string {
    const payload = b64url(
      Buffer.from(JSON.stringify({ ...tx, exp: Date.now() + TX_TTL_MS })),
    );
    return `${payload}.${sign(payload, config.sessionSecret)}`;
  }

  function readTxCookie(value: string): OidcTx | null {
    const [payload, sig] = value.split('.');
    if (!payload || !sig) return null;
    const expected = sign(payload, config.sessionSecret);
    const got = Buffer.from(sig);
    const exp = Buffer.from(expected);
    if (got.length !== exp.length || !timingSafeEqual(got, exp)) return null;
    try {
      const tx = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as OidcTx;
      if (!tx.state || !tx.verifier || tx.exp < Date.now()) return null;
      return tx;
    } catch {
      return null;
    }
  }

  function buildAuthTransaction(loginHint?: string): { url: string; cookie: string } {
    const state = b64url(randomBytes(24));
    const nonce = b64url(randomBytes(24));
    const verifier = b64url(randomBytes(48));
    const challenge = b64url(createHash('sha256').update(verifier).digest());
    const scopeList = config.scopes && config.scopes.length ? [...config.scopes] : ['openid'];
    if (!scopeList.includes('openid')) scopeList.unshift('openid');
    const scope = scopeList.join(' ');
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      response_type: 'code',
      scope,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    if (loginHint) params.set('login_hint', loginHint);
    return {
      url: `${issuer}/auth?${params}`,
      cookie: createTxCookie({ state, nonce, verifier }),
    };
  }

  async function completeAuthTransaction(
    params: URLSearchParams,
    txCookie: string | undefined,
  ): Promise<string> {
    const tx = txCookie ? readTxCookie(txCookie) : null;
    if (!tx) throw new OidcError('login transaction missing or expired');
    const state = params.get('state');
    const code = params.get('code');
    if (!state || !code || state !== tx.state) throw new OidcError('state mismatch');

    const res = await fetch(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.redirectUri,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        code_verifier: tx.verifier,
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
      throw new OidcError(`token endpoint ${res.status}: ${await res.text().catch(() => '')}`);
    }
    const data = (await res.json()) as { id_token?: string };
    if (!data.id_token) throw new OidcError('no id_token in response');

    const parts = data.id_token.split('.');
    if (parts.length !== 3) throw new OidcError('malformed id_token');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as {
      iss?: string;
      aud?: string | string[];
      sub?: string;
      exp?: number;
      nonce?: string;
    };
    const audOk = Array.isArray(claims.aud)
      ? claims.aud.includes(config.clientId)
      : claims.aud === config.clientId;
    if (claims.iss !== issuer || !audOk) throw new OidcError('iss/aud mismatch');
    if (!claims.exp || claims.exp * 1000 < Date.now()) throw new OidcError('id_token expired');
    if (claims.nonce !== tx.nonce) throw new OidcError('nonce mismatch');
    if (!claims.sub?.startsWith('did:')) throw new OidcError('sub is not a DID');
    return claims.sub;
  }

  return { buildAuthTransaction, completeAuthTransaction, createTxCookie, readTxCookie };
}
