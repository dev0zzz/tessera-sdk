import { test } from "node:test";
import assert from "node:assert/strict";
import { createOrgs, OrgsPdsError } from "../dist/orgs/index.js";

const ATTESTATION = "at.tessera.org.attestation";
const ORG = "did:plc:org111";
const MEMBER = "did:plc:member222";

/** Builds a fake fetch that maps a URL-substring -> Response. */
function fakeFetch(
  routes: Array<{
    match: string;
    status?: number;
    body?: unknown;
    throw?: boolean;
  }>,
): typeof fetch {
  return (async (input: string | URL): Promise<Response> => {
    const url = input.toString();
    const route = routes.find((r) => url.includes(r.match));
    if (!route) return new Response("null", { status: 404 });
    if (route.throw) throw new Error("network down");
    return new Response(JSON.stringify(route.body ?? null), {
      status: route.status ?? 200,
    });
  }) as typeof fetch;
}

const validAttestation = (overrides: Record<string, unknown> = {}) => ({
  match: "getRecord",
  body: {
    value: {
      $type: ATTESTATION,
      subject: MEMBER,
      role: "member",
      validFrom: "2020-01-01T00:00:00Z",
      ...overrides,
    },
  },
});

// --- verifyMembership ---

test("verifyMembership throws OrgsPdsError when the PDS is unreachable", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([{ match: "getRecord", throw: true }]),
  });
  await assert.rejects(() => orgs.verifyMembership(MEMBER, ORG), OrgsPdsError);
});

test("verifyMembership returns member:false when no attestation exists", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([
      { match: "getRecord", status: 400, body: { error: "RecordNotFound" } },
    ]),
  });
  assert.deepEqual(await orgs.verifyMembership(MEMBER, ORG), { member: false });
});

test("verifyMembership returns member:true with role for a valid attestation", async () => {
  const orgs = createOrgs({ fetch: fakeFetch([validAttestation()]) });
  assert.deepEqual(await orgs.verifyMembership(MEMBER, ORG), {
    member: true,
    role: "member",
  });
});

test("verifyMembership rejects when subject !== rkey (forged/copied)", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([validAttestation({ subject: "did:plc:someoneelse" })]),
  });
  assert.deepEqual(await orgs.verifyMembership(MEMBER, ORG), { member: false });
});

test("verifyMembership rejects before validFrom", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([validAttestation({ validFrom: "2999-01-01T00:00:00Z" })]),
  });
  assert.deepEqual(await orgs.verifyMembership(MEMBER, ORG), { member: false });
});

test("verifyMembership rejects after validUntil", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([
      validAttestation({ validUntil: "2000-01-01T00:00:00Z" }),
    ]),
  });
  assert.deepEqual(await orgs.verifyMembership(MEMBER, ORG), { member: false });
});

// --- listMembers ---

test("listMembers returns the org roster, filtering time-invalid rows", async () => {
  const orgs = createOrgs({
    fetch: fakeFetch([
      {
        match: "listRecords",
        body: {
          records: [
            {
              uri: "at://did:plc:org111/at.tessera.org.attestation/did:plc:a",
              value: {
                subject: "did:plc:a",
                role: "admin",
                validFrom: "2020-01-01T00:00:00Z",
              },
            },
            {
              uri: "at://did:plc:org111/at.tessera.org.attestation/did:plc:b",
              value: {
                subject: "did:plc:b",
                role: "member",
                validFrom: "2999-01-01T00:00:00Z",
              },
            },
          ],
        },
      },
    ]),
  });
  const members = await orgs.listMembers(ORG);
  assert.equal(members.length, 1);
  assert.deepEqual(members[0], {
    did: "did:plc:a",
    role: "admin",
    validFrom: "2020-01-01T00:00:00Z",
    validUntil: undefined,
  });
});

// --- listBadges ---

test("listBadges classifies flair / verified / unverified", async () => {
  const orgs = createOrgs({
    fetch: (async (input: string | URL): Promise<Response> => {
      const url = input.toString();
      if (url.includes("listRecords")) {
        return new Response(
          JSON.stringify({
            records: [
              {
                uri: "at://m/at.tessera.org.membership/1",
                value: { label: "Haus Slytherin" },
              },
              {
                uri: "at://m/at.tessera.org.membership/2",
                value: { label: "Spiral GmbH", org: "did:plc:verified" },
              },
              {
                uri: "at://m/at.tessera.org.membership/3",
                value: { label: "Ghost Inc", org: "did:plc:none" },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("getRecord") && url.includes("did%3Aplc%3Averified")) {
        return new Response(
          JSON.stringify({
            value: {
              subject: MEMBER,
              role: "member",
              validFrom: "2020-01-01T00:00:00Z",
            },
          }),
          { status: 200 },
        );
      }
      return new Response("null", { status: 400 }); // did:plc:none -> no attestation
    }) as typeof fetch,
  });
  const badges = await orgs.listBadges(MEMBER);
  assert.deepEqual(badges, [
    { label: "Haus Slytherin", state: "flair" },
    { label: "Spiral GmbH", org: "did:plc:verified", state: "verified" },
    { label: "Ghost Inc", org: "did:plc:none", state: "unverified" },
  ]);
});
