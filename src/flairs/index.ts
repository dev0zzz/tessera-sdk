/**
 * @tesseraat/sdk/flairs — read-only consumer client for Tessera flairs.
 * Fetch-only (no @atproto/api), isomorphic — the mirror of ./orgs for the
 * flair record triple:
 *
 *   at.tessera.flair.def    (issuer repo)  — the definition; policy open|granted
 *   at.tessera.flair.grant  (issuer repo)  — issuer grants def to subject;
 *                                            rkey MUST be "<def>:<subject>"
 *   at.tessera.flair.badge  (wearer repo)  — wearer wears (issuer, def);
 *                                            rkey MUST be "<issuer>:<def>"
 *
 * A wear is VERIFIED when the badge exists AND the def exists AND (the def is
 * `open` — the definition itself is the issuer's standing consent — or a
 * matching grant exists). Anything else fails closed, including an unknown
 * policy value.
 *
 * TRUST: like ./orgs, this trusts the PDS's responses as-is; it does not verify
 * repo signatures. Point it only at a trusted PDS.
 */
import { TESSERA_PDS } from "../core/index.js";

const FLAIR_DEF = "at.tessera.flair.def";
const FLAIR_GRANT = "at.tessera.flair.grant";
const FLAIR_BADGE = "at.tessera.flair.badge";

export interface FlairsConfig {
  /** PDS base URL, no trailing slash. Default: core's TESSERA_PDS. */
  pdsUrl?: string;
  /** Injectable fetch for tests. Default: globalThis.fetch. */
  fetch?: typeof fetch;
}

export type FlairPolicy = "open" | "granted";

export interface FlairStyle {
  shape?: string;
  tone?: string;
  icon?: string;
}

export interface FlairDef {
  issuer: string;
  rkey: string;
  name: string;
  description?: string;
  policy: FlairPolicy;
  criteria?: string;
  style?: FlairStyle;
  imageCid?: string;
  createdAt: string;
}

export interface WornFlair {
  issuer: string;
  def: string;
  name: string;
  policy: FlairPolicy;
  style?: FlairStyle;
  imageCid?: string;
}

/**
 * Thrown when the PDS is unreachable or returns a server error. Never thrown
 * for a missing record (that is a definitive "no").
 */
export class FlairsPdsError extends Error {}

export interface Flairs {
  getDef(issuerDid: string, defRkey: string): Promise<FlairDef | null>;
  listDefs(issuerDid: string): Promise<FlairDef[]>;
  /** Does a standing grant for (def, subject) exist in the issuer's repo? */
  verifyGrant(
    issuerDid: string,
    defRkey: string,
    subjectDid: string,
  ): Promise<boolean>;
  /** Both halves: the wearer's badge plus the issuer's def/grant counterpart. */
  verifyWear(
    wearerDid: string,
    issuerDid: string,
    defRkey: string,
  ): Promise<boolean>;
  listWornFlairs(wearerDid: string): Promise<WornFlair[]>;
}

export function createFlairs(config: FlairsConfig = {}): Flairs {
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
      throw new FlairsPdsError("Tessera PDS unreachable");
    }
    if (res.status === 404) return null;
    if (res.status === 400) {
      // 400 is RecordNotFound OR InvalidRequest/RepoNotFound/… Only a confirmed
      // not-found is a definitive "no"; anything else must surface, not silently
      // deny.
      const b = (await res.json().catch(() => null)) as {
        error?: string;
      } | null;
      if (b?.error === "RecordNotFound") return null;
      throw new FlairsPdsError(`PDS getRecord 400: ${b?.error ?? "unknown"}`);
    }
    if (!res.ok) throw new FlairsPdsError(`PDS getRecord failed: ${res.status}`);
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
        throw new FlairsPdsError("Tessera PDS unreachable");
      }
      if (!res.ok)
        throw new FlairsPdsError(`PDS listRecords failed: ${res.status}`);
      const data = (await res.json().catch(() => null)) as {
        records?: Array<{ uri: string; value: Record<string, unknown> }>;
        cursor?: string;
      } | null;
      if (data?.records) out.push(...data.records);
      if (!data?.cursor || data.cursor === cursor) break;
      cursor = data.cursor;
    } while (++pages < 50);
    return out;
  }

  /** Fail-closed parse: unknown policy or missing name → not a usable def. */
  function parseDef(
    issuer: string,
    rkey: string,
    v: Record<string, unknown>,
  ): FlairDef | null {
    if (typeof v.name !== "string" || v.name.length === 0) return null;
    if (v.policy !== "open" && v.policy !== "granted") return null;
    // style is presentation-only and not consent-bound (unlike name): extract
    // whatever string fields are present, uncapped and unvalidated. Values
    // outside the curated sets are the CONSUMER's fallback problem, per the
    // lexicon — not something to reject here.
    let style: FlairStyle | undefined;
    if (v.style && typeof v.style === "object" && !Array.isArray(v.style)) {
      const s = v.style as Record<string, unknown>;
      const extracted: FlairStyle = {};
      if (typeof s.shape === "string") extracted.shape = s.shape;
      if (typeof s.tone === "string") extracted.tone = s.tone;
      if (typeof s.icon === "string") extracted.icon = s.icon;
      if (Object.keys(extracted).length > 0) style = extracted;
    }
    // image is a blob ref; the JSON shape varies by transport. getRecord
    // normally serializes it as { ref: { $link }, ... } but some paths
    // (legacy writes, raw CBOR->JSON) surface the CID directly as { cid }.
    // Tolerate missing/malformed as absent — never throw on a bad image field.
    let imageCid: string | undefined;
    if (v.image && typeof v.image === "object" && !Array.isArray(v.image)) {
      const img = v.image as Record<string, unknown>;
      const ref = img.ref;
      if (ref && typeof ref === "object" && !Array.isArray(ref)) {
        const link = (ref as Record<string, unknown>).$link;
        if (typeof link === "string") imageCid = link;
      }
      if (!imageCid && typeof img.cid === "string") imageCid = img.cid;
    }
    return {
      issuer,
      rkey,
      name: v.name,
      policy: v.policy,
      ...(typeof v.description === "string"
        ? { description: v.description }
        : {}),
      ...(typeof v.criteria === "string" ? { criteria: v.criteria } : {}),
      ...(style ? { style } : {}),
      ...(imageCid ? { imageCid } : {}),
      createdAt: typeof v.createdAt === "string" ? v.createdAt : "",
    };
  }

  async function getDef(
    issuerDid: string,
    defRkey: string,
  ): Promise<FlairDef | null> {
    const rec = await getRecord(issuerDid, FLAIR_DEF, defRkey);
    if (!rec) return null;
    return parseDef(issuerDid, defRkey, rec.value);
  }

  async function listDefs(issuerDid: string): Promise<FlairDef[]> {
    const recs = await listRecords(issuerDid, FLAIR_DEF);
    const out: FlairDef[] = [];
    for (const r of recs) {
      const rkey = r.uri.split("/").pop() ?? "";
      const def = parseDef(issuerDid, rkey, r.value);
      if (def) out.push(def);
    }
    return out;
  }

  async function verifyGrant(
    issuerDid: string,
    defRkey: string,
    subjectDid: string,
  ): Promise<boolean> {
    // rkey IS "<def>:<subject>" per lexicon; the field check guards against a
    // record whose key and content disagree — that is an invalid record, not a
    // grant.
    const rec = await getRecord(
      issuerDid,
      FLAIR_GRANT,
      `${defRkey}:${subjectDid}`,
    );
    if (!rec) return false;
    return rec.value.def === defRkey && rec.value.subject === subjectDid;
  }

  async function verifyWear(
    wearerDid: string,
    issuerDid: string,
    defRkey: string,
  ): Promise<boolean> {
    const def = await getDef(issuerDid, defRkey);
    if (!def) return false;
    const badge = await getRecord(
      wearerDid,
      FLAIR_BADGE,
      `${issuerDid}:${defRkey}`,
    );
    if (!badge) return false;
    // The name the wearer agreed to. A def renamed after consent is a new
    // statement — when the badge carries a name and it no longer matches,
    // this is not a wear (fail closed). Badges from before the field existed
    // carry none and verify against the live name.
    const agreedName = badge.value.name;
    if (typeof agreedName === "string" && agreedName !== def.name) return false;
    // Bild-Bindung: exakt auf Bild-oder-Abwesenheit. Ein getauschtes, neu
    // hinzugefügtes oder entferntes Artwork ist eine neue Aussage, der niemand
    // zugestimmt hat — fail closed, wie beim Namen.
    const agreedImage = typeof badge.value.image === "string" ? badge.value.image : null;
    if ((def.imageCid ?? null) !== agreedImage) return false;
    if (def.policy === "open") return true;
    return verifyGrant(issuerDid, defRkey, wearerDid);
  }

  async function listWornFlairs(wearerDid: string): Promise<WornFlair[]> {
    const recs = await listRecords(wearerDid, FLAIR_BADGE);
    const out: WornFlair[] = [];
    const seen = new Set<string>();
    for (const r of recs) {
      const v = r.value;
      if (typeof v.issuer !== "string" || typeof v.def !== "string") continue;
      // The lexicon's key rule is part of the record's validity: a badge MUST
      // sit at "<issuer>:<def>", and a record whose key and fields disagree is
      // invalid, not a wear. Enforcing it here keeps this reader and verifyWear
      // (which reads exactly that key) answering the same question the same way.
      const rkey = r.uri.split("/").pop() ?? "";
      if (rkey !== `${v.issuer}:${v.def}`) continue;
      // One entry per (issuer, def): the PDS does not enforce the lexicon's key
      // rule for foreign lexicons, so any client can write duplicates under TID
      // rkeys — mirroring the dedupe in orgs' consumers.
      const key = `${v.issuer}\n${v.def}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const def = await getDef(v.issuer, v.def);
      if (!def) continue;
      // Same fail-closed rule as verifyWear: a badge naming the def it was
      // consented to must match the def's current name, or a rename has
      // turned it into an unagreed-to statement.
      if (typeof v.name === "string" && v.name !== def.name) continue;
      // Bild-Bindung: exakt auf Bild-oder-Abwesenheit. Ein getauschtes, neu
      // hinzugefügtes oder entferntes Artwork ist eine neue Aussage, der niemand
      // zugestimmt hat — fail closed, wie beim Namen.
      const agreedImage = typeof v.image === "string" ? v.image : null;
      if ((def.imageCid ?? null) !== agreedImage) continue;
      if (
        def.policy === "granted" &&
        !(await verifyGrant(v.issuer, v.def, wearerDid))
      ) {
        continue;
      }
      out.push({
        issuer: v.issuer,
        def: v.def,
        name: def.name,
        policy: def.policy,
        ...(def.style ? { style: def.style } : {}),
        ...(def.imageCid ? { imageCid: def.imageCid } : {}),
      });
    }
    return out;
  }

  return { getDef, listDefs, verifyGrant, verifyWear, listWornFlairs };
}
