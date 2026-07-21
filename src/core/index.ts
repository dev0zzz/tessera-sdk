/**
 * tessera-sdk/core — isomorphic helpers for talking to the Tessera PDS.
 * Extracted verbatim from salzgrotte/mbdrone's `src/lib/tessera.ts` (which
 * were byte-identical copies); the PDS URL is now overridable via
 * TESSERA_PDS_URL instead of being hardcoded per app.
 */

const DEFAULT_PDS = 'https://pds.tessera.at';

export const TESSERA_PDS: string =
  (typeof process !== 'undefined' && process.env?.TESSERA_PDS_URL) ||
  DEFAULT_PDS;

/** A handle that belongs to the tessera.at PDS, e.g. `mb.tessera.at`. */
export function isTesseraHandle(handle: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.tessera\.at$/i.test(handle);
}

/** Strip a leading @ and surrounding whitespace, lowercase the domain part. */
export function normalizeHandle(input: string): string {
  return input.trim().replace(/^@+/, '').toLowerCase();
}

export class HandleResolveError extends Error {}

/**
 * Resolves a handle to a DID via the tessera PDS `resolveHandle` endpoint.
 * Throws HandleResolveError with a German message on not-found / unreachable.
 * Uses a 5s timeout so a hung PDS can't stall the request.
 */
export async function resolveTesseraHandle(handle: string): Promise<string> {
  const url = `${TESSERA_PDS}/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`;
  let res: Response;
  try {
    res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  } catch {
    throw new HandleResolveError('Tessera ist gerade nicht erreichbar — bitte später erneut versuchen.');
  }
  if (res.status === 400 || res.status === 404) {
    throw new HandleResolveError('Kein Tessera-Konto mit diesem Handle gefunden.');
  }
  if (!res.ok) {
    throw new HandleResolveError('Tessera ist gerade nicht erreichbar — bitte später erneut versuchen.');
  }
  const data = (await res.json().catch(() => null)) as { did?: unknown } | null;
  if (!data || typeof data.did !== 'string' || !data.did.startsWith('did:')) {
    throw new HandleResolveError('Kein Tessera-Konto mit diesem Handle gefunden.');
  }
  return data.did;
}

/** Shorten a DID for display: keep the head and tail. */
export function shortenDid(did: string): string {
  return did.length > 26 ? `${did.slice(0, 16)}…${did.slice(-6)}` : did;
}

// in-memory DID→handle cache (process lifetime). Bootstrap DIDs rarely change,
// so this keeps login pickers from hitting the PDS on every render.
const didHandleCache = new Map<string, string>();

/**
 * Resolves a DID to its current handle via the PDS `describeRepo` endpoint,
 * with in-memory caching and a short timeout. Never throws: on failure it
 * returns (and does not cache) a shortened form of the DID so a login
 * picker can always render within a few seconds.
 */
export async function resolveDidToHandle(did: string): Promise<string> {
  const cached = didHandleCache.get(did);
  if (cached) return cached;
  const url = `${TESSERA_PDS}/xrpc/com.atproto.repo.describeRepo?repo=${encodeURIComponent(did)}`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(2500) });
    if (res.ok) {
      const data = (await res.json().catch(() => null)) as { handle?: unknown } | null;
      if (data && typeof data.handle === 'string' && data.handle && data.handle !== 'handle.invalid') {
        didHandleCache.set(did, data.handle);
        return data.handle;
      }
    }
  } catch {
    // fall through to the shortened-DID fallback
  }
  return shortenDid(did);
}
