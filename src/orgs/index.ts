/**
 * tessera-sdk/orgs — read-only consumer client for Tessera org membership.
 * Fetch-only (no @atproto/api), isomorphic. Verifies the authoritative
 * attestation in the org's repo (never the self-asserted membership in the
 * member's repo) and derives display badges from the member's memberships.
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
    if (res.status === 400 || res.status === 404) return null; // RecordNotFound
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
      cursor = data?.cursor;
    } while (cursor);
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
    const now = Date.now();
    if (typeof v.validFrom === "string" && Date.parse(v.validFrom) > now)
      return { member: false };
    if (typeof v.validUntil === "string" && Date.parse(v.validUntil) < now)
      return { member: false };
    return {
      member: true,
      role: typeof v.role === "string" ? v.role : undefined,
    };
  }

  async function listMembers(orgDid: string): Promise<OrgMember[]> {
    const recs = await listRecords(orgDid, ATTESTATION);
    const now = Date.now();
    const out: OrgMember[] = [];
    for (const r of recs) {
      const v = r.value;
      // subject === rkey is enforced server-side, so subject is trustworthy.
      if (
        typeof v.subject !== "string" ||
        typeof v.role !== "string" ||
        typeof v.validFrom !== "string"
      )
        continue;
      if (Date.parse(v.validFrom) > now) continue;
      if (typeof v.validUntil === "string" && Date.parse(v.validUntil) < now)
        continue;
      out.push({
        did: v.subject,
        role: v.role,
        validFrom: v.validFrom,
        validUntil: typeof v.validUntil === "string" ? v.validUntil : undefined,
      });
    }
    return out;
  }

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
