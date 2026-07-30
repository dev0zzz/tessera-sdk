import fs from 'node:fs';
import path from 'node:path';
import {
  buildAtprotoLoopbackClientMetadata,
  NodeOAuthClient,
  type NodeSavedSession,
  type NodeSavedState,
  type OAuthClientMetadataInput,
} from '@atproto/oauth-client-node';
import Database from 'better-sqlite3';

/**
 * @tesseraat/sdk/auth-node — direct atproto OAuth for NODE (server-side) apps
 * that read/write the user's repo as the user. Extracted from the
 * previously-triplicated NodeOAuthClient wiring in tessera-web / scrollpass
 * (SQLite state+session stores on a persistent volume, in-process refresh
 * lock). Identity-only apps use @tesseraat/sdk/oidc-rp instead.
 *
 * Peer dependencies: @atproto/oauth-client-node, better-sqlite3.
 */

// OAuth states are short-lived (one redirect roundtrip); anything older is junk.
const STATE_TTL_MS = 60 * 60 * 1000;

/**
 * Opens (or creates) the SQLite database holding the OAuth stores, with WAL
 * and the two tables. Keep the file on a persistent volume so sessions
 * survive deploys. The caller owns the handle (typically via a
 * globalThis singleton so dev module re-evals reuse one connection).
 */
export function openOAuthDb(dbPath: string): Database.Database {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS oauth_state (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_session (
      sub        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  return db;
}

/** The NodeOAuthClient state/session stores backed by `openOAuthDb`'s tables. */
export function createSqliteStores(db: Database.Database): {
  stateStore: {
    set(key: string, value: NodeSavedState): Promise<void>;
    get(key: string): Promise<NodeSavedState | undefined>;
    del(key: string): Promise<void>;
  };
  sessionStore: {
    set(sub: string, session: NodeSavedSession): Promise<void>;
    get(sub: string): Promise<NodeSavedSession | undefined>;
    del(sub: string): Promise<void>;
  };
} {
  return {
    stateStore: {
      async set(key, value) {
        db.prepare('DELETE FROM oauth_state WHERE created_at < ?').run(
          Date.now() - STATE_TTL_MS,
        );
        db.prepare(
          'INSERT OR REPLACE INTO oauth_state (key, value, created_at) VALUES (?, ?, ?)',
        ).run(key, JSON.stringify(value), Date.now());
      },
      async get(key) {
        const row = db
          .prepare('SELECT value FROM oauth_state WHERE key = ?')
          .get(key) as { value: string } | undefined;
        return row ? (JSON.parse(row.value) as NodeSavedState) : undefined;
      },
      async del(key) {
        db.prepare('DELETE FROM oauth_state WHERE key = ?').run(key);
      },
    },
    sessionStore: {
      async set(sub, session) {
        db.prepare(
          'INSERT OR REPLACE INTO oauth_session (sub, value, updated_at) VALUES (?, ?, ?)',
        ).run(sub, JSON.stringify(session), Date.now());
      },
      async get(sub) {
        const row = db
          .prepare('SELECT value FROM oauth_session WHERE sub = ?')
          .get(sub) as { value: string } | undefined;
        return row ? (JSON.parse(row.value) as NodeSavedSession) : undefined;
      },
      async del(sub) {
        db.prepare('DELETE FROM oauth_session WHERE sub = ?').run(sub);
      },
    },
  };
}

type Awaitable<T> = T | PromiseLike<T>;

const chains = new Map<string, Promise<unknown>>();

/**
 * In-process named lock for the OAuth client: serializes concurrent token
 * refreshes of the same session, which would otherwise invalidate each other
 * ("Credentials might get revoked"). Sufficient for single-container apps.
 */
export async function requestLock<T>(
  name: string,
  fn: () => Awaitable<T>,
): Promise<T> {
  const prev = chains.get(name) ?? Promise.resolve();
  // Join the existing chain; a predecessor's failure must not block us.
  const run = prev.then(
    () => fn(),
    () => fn(),
  );
  const settled = run.then(
    () => {},
    () => {},
  );
  chains.set(name, settled);
  try {
    return await run;
  } finally {
    if (chains.get(name) === settled) chains.delete(name);
  }
}

export interface NodeAuthConfig {
  /** Public app origin, e.g. `https://feed.tessera.at` (no trailing slash). */
  appUrl: string;
  /** Shown on the PDS consent screen (for non-trusted clients). */
  clientName: string;
  /** SQLite file for the OAuth stores — put it on a persistent volume. */
  dbPath: string;
  /** @default 'atproto transition:generic' */
  scope?: string;
}

/**
 * `true` iff `appUrl` is a plain-http loopback origin (`localhost` /
 * `127.0.0.1` / `[::1]`) — i.e. local dev, as opposed to a real https
 * deployment.
 */
function isLoopbackAppUrl(appUrl: string): boolean {
  const u = new URL(appUrl);
  return (
    u.protocol === 'http:' &&
    (u.hostname === 'localhost' ||
      u.hostname === '127.0.0.1' ||
      u.hostname === '[::1]' ||
      u.hostname === '::1')
  );
}

/**
 * Builds the `NodeOAuthClient` client-metadata for a given app origin.
 *
 * Split out as a pure function (rather than inlined in
 * `createTesseraNodeClient`) so it's testable without dragging in the SQLite
 * stores.
 *
 * Two branches:
 *
 * - **Prod** (`https://…`): the standard hosted client, identified by its
 *   `client-metadata.json` URL, exactly as before this fix.
 * - **Dev/loopback** (`http://localhost:*` or `http://127.0.0.1:*`): atproto
 *   OAuth (`@atproto/oauth-types`'s zod schemas) rejects `localhost` in
 *   `redirect_uris` per RFC 8252 (loopback redirects must use the literal IP,
 *   not the `localhost` name) and rejects a non-https `client_id`. We build
 *   the canonical atproto *loopback client* via
 *   `buildAtprotoLoopbackClientMetadata` instead, which needs no hosted
 *   metadata document at all: `client_id` becomes a self-describing
 *   `http://localhost?scope=…&redirect_uri=…` URL that PDSes accept as-is.
 *   The redirect URI's hostname is rewritten from whatever the caller passed
 *   (`localhost` or `127.0.0.1`) to `127.0.0.1` — so an env var of
 *   `http://localhost:3000` keeps working without every app having to know
 *   the RFC 8252 wrinkle. Because of that rewrite, **the callback lands on
 *   `127.0.0.1`**: the dev must browse the app via `http://127.0.0.1:<port>`,
 *   not `http://localhost:<port>` — cookies are origin-bound, so a
 *   `localhost` tab would not see the session set on the `127.0.0.1`
 *   callback.
 *
 * Prod behavior is byte-identical to before.
 */
export function buildClientMetadataForAppUrl(
  appUrl: string,
  clientName: string,
  scope?: string,
): OAuthClientMetadataInput {
  const normalizedAppUrl = appUrl.replace(/\/$/, '');
  const resolvedScope = scope ?? 'atproto transition:generic';

  if (isLoopbackAppUrl(normalizedAppUrl)) {
    const callbackUrl = new URL(`${normalizedAppUrl}/oauth/callback`);
    callbackUrl.hostname = '127.0.0.1';
    return buildAtprotoLoopbackClientMetadata({
      scope: resolvedScope,
      redirect_uris: [callbackUrl.toString()],
    });
  }

  return {
    client_id: `${normalizedAppUrl}/client-metadata.json`,
    client_name: clientName,
    client_uri: normalizedAppUrl,
    redirect_uris: [`${normalizedAppUrl}/oauth/callback`],
    scope: resolvedScope,
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: 'web',
    token_endpoint_auth_method: 'none',
    dpop_bound_access_tokens: true,
  };
}

/**
 * The standard Tessera app client: hosted client-metadata at
 * `${appUrl}/client-metadata.json`, callback at `${appUrl}/oauth/callback`,
 * DPoP, SQLite stores, refresh lock. Call once and keep the instance (e.g.
 * behind a globalThis singleton) — it owns the database connection.
 *
 * For loopback `appUrl`s (local dev), see `buildClientMetadataForAppUrl`.
 */
export function createTesseraNodeClient(config: NodeAuthConfig): NodeOAuthClient {
  const appUrl = config.appUrl.replace(/\/$/, '');
  const db = openOAuthDb(config.dbPath);
  const { stateStore, sessionStore } = createSqliteStores(db);

  return new NodeOAuthClient({
    requestLock,
    clientMetadata: buildClientMetadataForAppUrl(
      appUrl,
      config.clientName,
      config.scope,
    ),
    stateStore,
    sessionStore,
  });
}
