/**
 * tessera-sdk/orgs — read-only consumer client for Tessera org membership.
 * Fetch-only (no @atproto/api), isomorphic. Verifies the authoritative
 * attestation in the org's repo (never the self-asserted membership in the
 * member's repo) and derives display badges from the member's memberships.
 *
 * TRUST: this client trusts the PDS's getRecord/listRecords response as-is; it
 * does not verify the atproto repo signature against the DID's signing key. A
 * hostile or MITM'd PDS (or a bad `pdsUrl`) can forge membership. Point it only
 * at a trusted PDS.
 */
import { TESSERA_PDS } from "../core/index.js";

const ATTESTATION = "at.tessera.org.attestation";
const MEMBERSHIP = "at.tessera.org.membership";

export interface OrgsConfig {
  /** PDS base URL, no trailing slash. Default: core's TESSERA_PDS. */
  pdsUrl?: string;
  /** Injectable fetch for tests. Default: globalThis.fetch. */
  fetch?: typeof fetch;
}

export interface Membership {
  member: boolean;
  role?: string;
}

export interface OrgMember {
  did: string;
  role: string;
  validFrom: string;
  validUntil?: string;
}

export type BadgeState = "verified" | "unverified" | "flair";

export interface Badge {
  label: string;
  org?: string;
  state: BadgeState;
}

/**
 * Thrown when the PDS is unreachable or returns a server error. Never thrown
 * for a missing record (that is a definitive "not a member").
 */
export class OrgsPdsError extends Error {}

export interface Orgs {
  verifyMembership(memberDid: string, orgDid: string): Promise<Membership>;
  listMembers(orgDid: string): Promise<OrgMember[]>;
  listBadges(memberDid: string): Promise<Badge[]>;
}

/**
 * Fail-closed time-window check for an attestation. Returns true ONLY if
 * validFrom is a valid, already-past datetime string and validUntil (if
 * present) is a valid, still-future datetime string. Missing validFrom, a
 * non-string, or an unparseable date (Date.parse → NaN) → false — a malformed
 * or number-typed bound must never silently grant or fail to revoke access.
 */
function withinValidWindow(v: Record<string, unknown>): boolean {
  const now = Date.now();
  const from = typeof v.validFrom === "string" ? Date.parse(v.validFrom) : NaN;
  if (!Number.isFinite(from) || from > now) return false;
  if (v.validUntil !== undefined) {
    const until =
      typeof v.validUntil === "string" ? Date.parse(v.validUntil) : NaN;
    if (!Number.isFinite(until) || until < now) return false;
  }
  return true;
}

export function createOrgs(config: OrgsConfig = {}): Orgs {
  const pds = (config.pdsUrl ?? TESSERA_PDS).replace(/\/$/, "");
  const fetchFn = config.fetch ?? globalThis.fetch;
  const TIMEOUT = 5000;

  async function getRecord(
    repo: string,
    collection: string,
    rkey: string,
  ): Promise<{ value: Record<string, unknown> } | null> {
    const url =
      `${pds}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(repo)}` +
      `&collection=${collection}&rkey=${encodeURIComponent(rkey)}`;
    let res: Response;
    try {
      res = await fetchFn(url, { signal: AbortSignal.timeout(TIMEOUT) });
    } catch {
      throw new OrgsPdsError("Tessera PDS unreachable");
    }
    if (res.status === 404) return null;
    if (res.status === 400) {
      // 400 is RecordNotFound OR InvalidRequest/RepoNotFound/… Only a confirmed
      // not-found is "not a member"; anything else is an error we must surface,
      // not silently deny (which would lock out a real member).
      const b = (await res.json().catch(() => null)) as {
        error?: string;
      } | null;
      if (b?.error === "RecordNotFound") return null;
      throw new OrgsPdsError(`PDS getRecord 400: ${b?.error ?? "unknown"}`);
    }
    if (!res.ok) throw new OrgsPdsError(`PDS getRecord failed: ${res.status}`);
    const data = (await res.json().catch(() => null)) as {
      value?: Record<string, unknown>;
    } | null;
    return data && data.value ? { value: data.value } : null;
  }

  async function listRecords(
    repo: string,
    collection: string,
  ): Promise<Array<{ uri: string; value: Record<string, unknown> }>> {
    const out: Array<{ uri: string; value: Record<string, unknown> }> = [];
    let cursor: string | undefined;
    let pages = 0;
    do {
      const url =
        `${pds}/xrpc/com.atproto.repo.listRecords?repo=${encodeURIComponent(repo)}` +
        `&collection=${collection}&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      let res: Response;
      try {
        res = await fetchFn(url, { signal: AbortSignal.timeout(TIMEOUT) });
      } catch {
        throw new OrgsPdsError("Tessera PDS unreachable");
      }
      if (!res.ok)
        throw new OrgsPdsError(`PDS listRecords failed: ${res.status}`);
      const data = (await res.json().catch(() => null)) as {
        records?: Array<{ uri: string; value: Record<string, unknown> }>;
        cursor?: string;
      } | null;
      if (data?.records) out.push(...data.records);
      // Stop on a non-advancing cursor (a malformed/hostile PDS returning the
      // same cursor would otherwise loop forever) and cap total pages.
      if (!data?.cursor || data.cursor === cursor) break;
      cursor = data.cursor;
    } while (++pages < 50);
    return out;
  }

  async function verifyMembership(
    memberDid: string,
    orgDid: string,
  ): Promise<Membership> {
    const rec = await getRecord(orgDid, ATTESTATION, memberDid);
    if (!rec) return { member: false };
    const v = rec.value;
    if (v.subject !== memberDid) return { member: false };
    if (!withinValidWindow(v)) return { member: false };
    return {
      member: true,
      role: typeof v.role === "string" ? v.role : undefined,
    };
  }

  async function listMembers(orgDid: string): Promise<OrgMember[]> {
    const recs = await listRecords(orgDid, ATTESTATION);
    const out: OrgMember[] = [];
    for (const r of recs) {
      const v = r.value;
      // subject === rkey is enforced server-side, so subject is trustworthy.
      if (typeof v.subject !== "string" || typeof v.role !== "string") continue;
      if (!withinValidWindow(v)) continue; // fail-closed, handles NaN/non-string
      out.push({
        did: v.subject,
        role: v.role,
        validFrom: v.validFrom as string, // guaranteed string by withinValidWindow
        validUntil: typeof v.validUntil === "string" ? v.validUntil : undefined,
      });
    }
    return out;
  }

  // NOTE for consumers: `label` and `org` come from the member's OWN repo and
  // are self-asserted. `state:'verified'` means only "the org DID `org`
  // attests this member" — NOT that `org` is the real organisation behind
  // `label`. A user can set label:'Spiral GmbH' pointing at an org DID they
  // control. Consumers MUST check `org` against a known-org allowlist before
  // trusting `label`; never render a bare "✓ {label}".
  async function listBadges(memberDid: string): Promise<Badge[]> {
    const recs = await listRecords(memberDid, MEMBERSHIP);
    const out: Badge[] = [];
    for (const r of recs) {
      const v = r.value;
      const label = typeof v.label === "string" ? v.label : "";
      const org = typeof v.org === "string" ? v.org : undefined;
      if (!org) {
        out.push({ label, state: "flair" });
        continue;
      }
      const { member } = await verifyMembership(memberDid, org); // local fn, no `this`
      out.push({ label, org, state: member ? "verified" : "unverified" });
    }
    return out;
  }

  return { verifyMembership, listMembers, listBadges };
}
