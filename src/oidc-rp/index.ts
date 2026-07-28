import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * @tesseraat/sdk/oidc-rp — minimal OIDC relying-party client for id.tessera.at
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

/** Why a login-transaction cookie could not be used. */
export type TxFailureReason =
  /** No cookie reached us — check cookie attributes and the redirect chain. */
  | 'absent'
  /** Present but not our format — truncated, or a leftover from another app. */
  | 'malformed'
  /** Signed with a different `sessionSecret` — key rotation or config mismatch. */
  | 'bad-signature'
  /** Aged out (10 min) — the user took too long between start and callback. */
  | 'expired'
  /** Well-formed and authentic, but missing `state`/`verifier`. */
  | 'incomplete';

type TxInspection = { ok: true; tx: OidcTx } | { ok: false; reason: TxFailureReason };

export class OidcError extends Error {
  /**
   * Set when the failure was the login-transaction cookie. Lets a caller log the
   * precise fault and treat a merely-lost cookie differently from a signature
   * mismatch, which can signal tampering.
   */
  readonly reason?: TxFailureReason;

  constructor(message: string, reason?: TxFailureReason) {
    super(message);
    this.reason = reason;
  }
}

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
  /**
   * URL that ends the Tessera session (OIDC RP-initiated logout). Send the user
   * here AFTER clearing your own session — otherwise the issuer session lives on
   * and the next login is waved through without asking for the passkey.
   *
   * `client_id` identifies the client, so no `id_token_hint` (and no storing of
   * raw ID tokens) is needed.
   *
   * The user is returned to your app's own origin by default (derived from
   * `redirectUri`) — no configuration needed. Pass `postLogoutRedirectUri` only
   * to land somewhere more specific; it must then be registered with the issuer,
   * otherwise it is ignored and the user stays on Tessera's "signed out" page.
   */
  buildEndSessionUrl(opts?: { postLogoutRedirectUri?: string; state?: string }): string;
}

export function createOidcRp(config: OidcRpConfig): OidcRp {
  const issuer = config.issuer.replace(/\/$/, '');

  function createTxCookie(tx: Omit<OidcTx, 'exp'>): string {
    const payload = b64url(
      Buffer.from(JSON.stringify({ ...tx, exp: Date.now() + TX_TTL_MS })),
    );
    return `${payload}.${sign(payload, config.sessionSecret)}`;
  }

  /**
   * Same check as readTxCookie, but says WHY it failed.
   *
   * Collapsing every cause into one null was a diagnosability dead end: a
   * cookie the browser never sent, one signed with a different secret, and one
   * that simply aged out are three very different faults — the first points at
   * cookie attributes or a redirect chain, the second at a key/config mismatch,
   * the third at a user who took too long. Callers can log the reason and, for
   * example, silently restart a login that merely lost its cookie.
   */
  function inspectTxCookie(value: string | undefined): TxInspection {
    if (!value) return { ok: false, reason: 'absent' };
    const [payload, sig] = value.split('.');
    if (!payload || !sig) return { ok: false, reason: 'malformed' };
    const expected = sign(payload, config.sessionSecret);
    const got = Buffer.from(sig);
    const exp = Buffer.from(expected);
    if (got.length !== exp.length || !timingSafeEqual(got, exp)) {
      return { ok: false, reason: 'bad-signature' };
    }
    let tx: OidcTx;
    try {
      tx = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as OidcTx;
    } catch {
      return { ok: false, reason: 'malformed' };
    }
    if (!tx.state || !tx.verifier) return { ok: false, reason: 'incomplete' };
    if (tx.exp < Date.now()) return { ok: false, reason: 'expired' };
    return { ok: true, tx };
  }

  function readTxCookie(value: string): OidcTx | null {
    const seen = inspectTxCookie(value);
    return seen.ok ? seen.tx : null;
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
    const seen = inspectTxCookie(txCookie);
    if (!seen.ok) {
      throw new OidcError(`login transaction unusable: ${seen.reason}`, seen.reason);
    }
    const tx = seen.tx;
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

  function buildEndSessionUrl(opts?: { postLogoutRedirectUri?: string; state?: string }): string {
    const params = new URLSearchParams({ client_id: config.clientId });
    // Default the return target to the app's own origin, derived from the
    // registered redirect URI. That makes "logout brings me back" the standard
    // behaviour for every app without a line of extra config — and it is an
    // address the app already controls (it receives the authorization code
    // there), so it adds no redirect surface. A malformed redirectUri simply
    // yields no default rather than throwing.
    let derived: string | undefined;
    try {
      derived = new URL(config.redirectUri).origin;
    } catch {
      derived = undefined;
    }
    const target = opts?.postLogoutRedirectUri ?? derived;
    if (target) params.set('post_logout_redirect_uri', target);
    if (opts?.state) params.set('state', opts.state);
    return `${issuer}/session/end?${params}`;
  }

  return {
    buildAuthTransaction,
    completeAuthTransaction,
    createTxCookie,
    readTxCookie,
    buildEndSessionUrl,
  };
}
