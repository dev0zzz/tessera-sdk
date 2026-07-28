import fs from 'node:fs';
import path from 'node:path';
import {
  NodeOAuthClient,
  type NodeSavedSession,
  type NodeSavedState,
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
 * The standard Tessera app client: hosted client-metadata at
 * `${appUrl}/client-metadata.json`, callback at `${appUrl}/oauth/callback`,
 * DPoP, SQLite stores, refresh lock. Call once and keep the instance (e.g.
 * behind a globalThis singleton) — it owns the database connection.
 */
export function createTesseraNodeClient(config: NodeAuthConfig): NodeOAuthClient {
  const appUrl = config.appUrl.replace(/\/$/, '');
  const db = openOAuthDb(config.dbPath);
  const { stateStore, sessionStore } = createSqliteStores(db);

  return new NodeOAuthClient({
    requestLock,
    clientMetadata: {
      client_id: `${appUrl}/client-metadata.json`,
      client_name: config.clientName,
      client_uri: appUrl,
      redirect_uris: [`${appUrl}/oauth/callback`],
      scope: config.scope ?? 'atproto transition:generic',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    },
    stateStore,
    sessionStore,
  });
}
