import { Agent } from '@atproto/api';
import {
  BrowserOAuthClient,
  type OAuthSession,
} from '@atproto/oauth-client-browser';

/**
 * tessera-sdk/auth-browser — direct atproto OAuth for BROWSER apps that
 * read/write the user's repo as the user (the "needs an Agent" side of the
 * decision rule; identity-only apps use tessera-sdk/oidc-rp instead).
 * Extracted from skytess's src/game/auth.ts.
 *
 * Peer dependencies: @atproto/api, @atproto/oauth-client-browser.
 */

export interface AuthState {
  did: string;
  handle: string;
}

export interface BrowserAuthConfig {
  /** Hosted client-metadata URL used in production, e.g. `https://app.tessera.at/client-metadata.json`. */
  clientId: string;
  /** @default 'https://tessera.at' */
  handleResolver?: string;
  /** PDS the sign-in flow is sent to. @default 'https://pds.tessera.at' */
  pdsUrl?: string;
}

export interface BrowserAuth {
  /** Session restore + OAuth callback consumption. Call once, before the app renders its final UI. */
  initAuth(): Promise<AuthState | null>;
  /**
   * Starts the PDS connect flow (redirect; never resolves on success).
   * Passing the PDS URL (not a handle) plus an explicit prompt sends the
   * user straight to the passkey dialog / account creation — no name
   * typing, no "Welcome" interstitial. The passkey IS the identity.
   * NOTE: skipping the PDS's Authorize consent additionally requires the
   * app's client_id in the PDS's PDS_OAUTH_TRUSTED_CLIENTS list.
   */
  signIn(intent?: 'login' | 'create'): Promise<never>;
  signOut(): Promise<void>;
  /** The authed Agent for repo reads/writes, or null when signed out. */
  getAgent(): Agent | null;
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname.startsWith('127.') ||
    hostname === '[::1]'
  );
}

export function createBrowserAuth(config: BrowserAuthConfig): BrowserAuth {
  const handleResolver = config.handleResolver ?? 'https://tessera.at';
  const pdsUrl = config.pdsUrl ?? 'https://pds.tessera.at';

  let clientPromise: Promise<BrowserOAuthClient> | null = null;
  let agent: Agent | null = null;

  /**
   * Dev (localhost/127.*): loopback client — omitting `clientMetadata` makes
   * the lib derive a `http://localhost?redirect_uri=...` client_id from
   * `window.location` itself (see @atproto/oauth-client-browser README
   * "Using in development (localhost)"); the OAuth server special-cases this
   * client_id. Prod: real hosted client-metadata.json via `load`.
   */
  function makeClient(): Promise<BrowserOAuthClient> {
    if (isLoopbackHost(window.location.hostname)) {
      return Promise.resolve(new BrowserOAuthClient({ handleResolver }));
    }
    return BrowserOAuthClient.load({ clientId: config.clientId, handleResolver });
  }

  function getClient(): Promise<BrowserOAuthClient> {
    if (!clientPromise) clientPromise = makeClient();
    return clientPromise;
  }

  async function toAuthState(session: OAuthSession): Promise<AuthState> {
    agent = new Agent(session);
    try {
      const { data } = await agent.com.atproto.repo.describeRepo({ repo: session.sub });
      return { did: session.sub, handle: data.handle };
    } catch (err) {
      console.warn('[tessera-sdk/auth] could not resolve handle for', session.sub, err);
      return { did: session.sub, handle: session.sub };
    }
  }

  return {
    async initAuth() {
      try {
        const client = await getClient();
        const result = await client.init();
        if (!result) return null;
        return await toAuthState(result.session);
      } catch (err) {
        console.warn('[tessera-sdk/auth] initAuth failed', err);
        return null;
      }
    },

    async signIn(intent = 'login') {
      const client = await getClient();
      return client.signInRedirect(pdsUrl, { prompt: intent });
    },

    async signOut() {
      try {
        const client = await getClient();
        const sub = agent?.did;
        agent = null;
        if (sub) await client.revoke(sub);
      } catch (err) {
        console.warn('[tessera-sdk/auth] signOut failed', err);
      }
    },

    getAgent() {
      return agent;
    },
  };
}
