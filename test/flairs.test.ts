import { test } from "node:test";
import assert from "node:assert/strict";
import { createFlairs, FlairsPdsError } from "../dist/flairs/index.js";

const ISSUER = "did:plc:issuer111";
const WEARER = "did:plc:wearer222";
const DEF = "skytess-pilot";

/** Builds a fake fetch that maps a URL-substring -> Response. */
function fakeFetch(
  routes: Array<{ match: string; status?: number; body?: unknown; throw?: boolean }>,
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

const NOT_FOUND = { status: 400, body: { error: "RecordNotFound" } };

// URL-Anker: getRecord-URLs tragen collection= und rkey= als Query-Parameter,
// darüber lassen sich def-, grant- und badge-Reads im Fake auseinanderhalten.
const defRoute = (policy: string) => ({
  match: `collection=at.tessera.flair.def`,
  body: { value: { name: "Skytess-Pilot", policy, createdAt: "2026-01-01T00:00:00Z" } },
});
const grantRoute = {
  match: `collection=at.tessera.flair.grant`,
  body: { value: { def: DEF, subject: WEARER, createdAt: "2026-01-01T00:00:00Z" } },
};
const badgeRoute = {
  match: `collection=at.tessera.flair.badge&rkey=`,
  body: { value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" } },
};
const badgeRouteWithName = (name: string) => ({
  match: `collection=at.tessera.flair.badge&rkey=`,
  body: {
    value: { issuer: ISSUER, def: DEF, name, createdAt: "2026-01-01T00:00:00Z" },
  },
});
const IMAGE_CID = "bafyimagecid123";
const defRouteWithImage = (cid: string) => ({
  match: `collection=at.tessera.flair.def`,
  body: {
    value: {
      name: "Skytess-Pilot",
      policy: "open",
      image: { $type: "blob", ref: { $link: cid }, mimeType: "image/png", size: 1234 },
      createdAt: "2026-01-01T00:00:00Z",
    },
  },
});
const badgeRouteWithImage = (cid: string) => ({
  match: `collection=at.tessera.flair.badge&rkey=`,
  body: {
    value: { issuer: ISSUER, def: DEF, image: cid, createdAt: "2026-01-01T00:00:00Z" },
  },
});

test("getDef returns null when the record does not exist", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([{ match: "flair.def", ...NOT_FOUND }]),
  });
  assert.equal(await flairs.getDef(ISSUER, DEF), null);
});

test("getDef parses a valid def", async () => {
  const flairs = createFlairs({ fetch: fakeFetch([defRoute("open")]) });
  const def = await flairs.getDef(ISSUER, DEF);
  assert.equal(def?.name, "Skytess-Pilot");
  assert.equal(def?.policy, "open");
  assert.equal(def?.issuer, ISSUER);
  assert.equal(def?.rkey, DEF);
});

test("getDef fails closed on an unknown policy", async () => {
  const flairs = createFlairs({ fetch: fakeFetch([defRoute("secret")]) });
  assert.equal(await flairs.getDef(ISSUER, DEF), null);
});

test("getDef parses a curated style", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: `collection=at.tessera.flair.def`,
        body: {
          value: {
            name: "Skytess-Pilot",
            policy: "open",
            style: { shape: "seal", tone: "heart", icon: "trophy" },
            createdAt: "2026-01-01T00:00:00Z",
          },
        },
      },
    ]),
  });
  const def = await flairs.getDef(ISSUER, DEF);
  assert.deepEqual(def?.style, { shape: "seal", tone: "heart", icon: "trophy" });
});

test("getDef tolerates garbage style, keeping only the string fields", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: `collection=at.tessera.flair.def`,
        body: {
          value: {
            name: "Skytess-Pilot",
            policy: "open",
            style: { shape: 7, tone: null, icon: "star" },
            createdAt: "2026-01-01T00:00:00Z",
          },
        },
      },
    ]),
  });
  const def = await flairs.getDef(ISSUER, DEF);
  assert.deepEqual(def?.style, { icon: "star" });
});

test("getDef throws FlairsPdsError when the PDS is unreachable", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([{ match: "flair.def", throw: true }]),
  });
  await assert.rejects(() => flairs.getDef(ISSUER, DEF), FlairsPdsError);
});

test("verifyWear: open def + badge = true", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("open"), badgeRoute]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), true);
});

test("verifyWear: legacy badge without a name field still verifies against the live name (pre-binding)", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("open"), badgeRoute]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), true);
});

test("verifyWear: badge name matches the def's current name = true", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("open"), badgeRouteWithName("Skytess-Pilot")]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), true);
});

test("verifyWear: badge name mismatches the def's current (renamed) name = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("open"), badgeRouteWithName("Altname")]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("verifyWear: open def without badge = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      defRoute("open"),
      { match: "flair.badge", ...NOT_FOUND },
    ]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("verifyWear: granted def + badge + grant = true", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("granted"), badgeRoute, grantRoute]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), true);
});

test("verifyWear: granted def + badge WITHOUT grant = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      defRoute("granted"),
      badgeRoute,
      { match: "flair.grant", ...NOT_FOUND },
    ]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("verifyGrant rejects a grant whose fields mismatch the ask", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: "flair.grant",
        body: { value: { def: "other-def", subject: WEARER, createdAt: "2026-01-01T00:00:00Z" } },
      },
    ]),
  });
  assert.equal(await flairs.verifyGrant(ISSUER, DEF, WEARER), false);
});

test("listWornFlairs drops a badge whose def is gone and keeps verified ones", async () => {
  const goneIssuer = "did:plc:gone999";
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: "listRecords",
        body: {
          records: [
            {
              uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
              value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
            },
            {
              uri: `at://${WEARER}/at.tessera.flair.badge/${goneIssuer}:x`,
              value: { issuer: goneIssuer, def: "x", createdAt: "2026-01-01T00:00:00Z" },
            },
          ],
        },
      },
      // Der eine Issuer antwortet mit einer offenen Def, der andere mit 400.
      { match: `repo=${encodeURIComponent(goneIssuer)}`, ...NOT_FOUND },
      defRoute("open"),
    ]),
  });
  const worn = await flairs.listWornFlairs(WEARER);
  assert.deepEqual(worn, [
    { issuer: ISSUER, def: DEF, name: "Skytess-Pilot", policy: "open" },
  ]);
});

test("getDef returns null on a literal HTTP 404", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([{ match: "flair.def", status: 404 }]),
  });
  assert.equal(await flairs.getDef(ISSUER, DEF), null);
});

test("listWornFlairs includes a granted flair only while the grant stands", async () => {
  const badgeList = {
    match: "listRecords",
    body: {
      records: [
        {
          uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
          value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
        },
      ],
    },
  };
  const withGrant = createFlairs({
    fetch: fakeFetch([badgeList, defRoute("granted"), grantRoute]),
  });
  assert.deepEqual(await withGrant.listWornFlairs(WEARER), [
    { issuer: ISSUER, def: DEF, name: "Skytess-Pilot", policy: "granted" },
  ]);
  const withoutGrant = createFlairs({
    fetch: fakeFetch([
      badgeList,
      defRoute("granted"),
      { match: "flair.grant", ...NOT_FOUND },
    ]),
  });
  assert.deepEqual(await withoutGrant.listWornFlairs(WEARER), []);
});

test("listWornFlairs carries the def's style on the returned WornFlair", async () => {
  const badgeList = {
    match: "listRecords",
    body: {
      records: [
        {
          uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
          value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
        },
      ],
    },
  };
  const styledDefRoute = {
    match: `collection=at.tessera.flair.def`,
    body: {
      value: {
        name: "Skytess-Pilot",
        policy: "open",
        style: { shape: "band", tone: "spade", icon: "wing" },
        createdAt: "2026-01-01T00:00:00Z",
      },
    },
  };
  const flairs = createFlairs({ fetch: fakeFetch([badgeList, styledDefRoute]) });
  assert.deepEqual(await flairs.listWornFlairs(WEARER), [
    {
      issuer: ISSUER,
      def: DEF,
      name: "Skytess-Pilot",
      policy: "open",
      style: { shape: "band", tone: "spade", icon: "wing" },
    },
  ]);
});

test("listWornFlairs drops a badge whose key disagrees with its fields", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: "listRecords",
        body: {
          records: [
            {
              // TID rkey instead of the canonical "<issuer>:<def>" — the
              // lexicon calls this invalid, and verifyWear would say false.
              uri: `at://${WEARER}/at.tessera.flair.badge/3jui7kd54zh2y`,
              value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
            },
          ],
        },
      },
      defRoute("open"),
    ]),
  });
  assert.deepEqual(await flairs.listWornFlairs(WEARER), []);
});

test("verifyWear stays false for a badge stored under a non-canonical key", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      defRoute("open"),
      { match: "flair.badge", ...NOT_FOUND },
    ]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("listWornFlairs drops a badge whose stored name mismatches the def's current (renamed) name", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([
      {
        match: "listRecords",
        body: {
          records: [
            {
              uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
              value: {
                issuer: ISSUER,
                def: DEF,
                name: "Altname",
                createdAt: "2026-01-01T00:00:00Z",
              },
            },
          ],
        },
      },
      defRoute("open"),
    ]),
  });
  assert.deepEqual(await flairs.listWornFlairs(WEARER), []);
});

test("verifyWear: def image CID matches badge.image = true", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRouteWithImage(IMAGE_CID), badgeRouteWithImage(IMAGE_CID)]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), true);
});

test("verifyWear: def image CID differs from badge.image = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRouteWithImage(IMAGE_CID), badgeRouteWithImage("bafyother999")]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("verifyWear: def has an image but the badge has no image field = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRouteWithImage(IMAGE_CID), badgeRoute]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("verifyWear: badge carries an image but the def has none = false", async () => {
  const flairs = createFlairs({
    fetch: fakeFetch([defRoute("open"), badgeRouteWithImage(IMAGE_CID)]),
  });
  assert.equal(await flairs.verifyWear(WEARER, ISSUER, DEF), false);
});

test("listWornFlairs caps verification at MAX_WORN_CHECKS (30 of 31 badges checked)", async () => {
  const N = 31;
  const records = Array.from({ length: N }, (_, i) => {
    const issuer = `did:plc:issuer${String(i).padStart(3, "0")}`;
    return {
      uri: `at://${WEARER}/at.tessera.flair.badge/${issuer}:${DEF}`,
      value: { issuer, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
    };
  });
  let defReads = 0;
  const flairs = createFlairs({
    fetch: (async (input: string | URL): Promise<Response> => {
      const url = input.toString();
      if (url.includes("listRecords")) {
        return new Response(JSON.stringify({ records }), { status: 200 });
      }
      if (url.includes("collection=at.tessera.flair.def")) {
        defReads++;
        return new Response(
          JSON.stringify({
            value: { name: "Skytess-Pilot", policy: "open", createdAt: "2026-01-01T00:00:00Z" },
          }),
          { status: 200 },
        );
      }
      return new Response("null", { status: 404 });
    }) as typeof fetch,
  });
  const worn = await flairs.listWornFlairs(WEARER);
  assert.equal(worn.length, 30, "at most MAX_WORN_CHECKS entries are returned");
  assert.equal(defReads, 30, "only the first 30 deduped badges are ever verified");
});

test("listWornFlairs: a limit parameter narrows the cap but never raises it", async () => {
  const N = 10;
  const records = Array.from({ length: N }, (_, i) => {
    const issuer = `did:plc:issuer${String(i).padStart(3, "0")}`;
    return {
      uri: `at://${WEARER}/at.tessera.flair.badge/${issuer}:${DEF}`,
      value: { issuer, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
    };
  });
  const flairs = createFlairs({
    fetch: (async (input: string | URL): Promise<Response> => {
      const url = input.toString();
      if (url.includes("listRecords")) {
        return new Response(JSON.stringify({ records }), { status: 200 });
      }
      if (url.includes("collection=at.tessera.flair.def")) {
        return new Response(
          JSON.stringify({
            value: { name: "Skytess-Pilot", policy: "open", createdAt: "2026-01-01T00:00:00Z" },
          }),
          { status: 200 },
        );
      }
      return new Response("null", { status: 404 });
    }) as typeof fetch,
  });
  assert.equal((await flairs.listWornFlairs(WEARER, 3)).length, 3);
  // Asking for more than MAX_WORN_CHECKS is clamped down, not honored.
  assert.equal((await flairs.listWornFlairs(WEARER, 1000)).length, 10);
});

test("listWornFlairs: one badge's def-fetch rejecting does not drop the others (parallel, fail-closed per pair)", async () => {
  const failIssuer = "did:plc:failing777";
  const records = [
    {
      uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
      value: { issuer: ISSUER, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
    },
    {
      uri: `at://${WEARER}/at.tessera.flair.badge/${failIssuer}:${DEF}`,
      value: { issuer: failIssuer, def: DEF, createdAt: "2026-01-01T00:00:00Z" },
    },
  ];
  const flairs = createFlairs({
    fetch: (async (input: string | URL): Promise<Response> => {
      const url = input.toString();
      if (url.includes("listRecords")) {
        return new Response(JSON.stringify({ records }), { status: 200 });
      }
      if (url.includes(`repo=${encodeURIComponent(failIssuer)}`)) {
        throw new Error("network down");
      }
      if (url.includes("collection=at.tessera.flair.def")) {
        return new Response(
          JSON.stringify({
            value: { name: "Skytess-Pilot", policy: "open", createdAt: "2026-01-01T00:00:00Z" },
          }),
          { status: 200 },
        );
      }
      return new Response("null", { status: 404 });
    }) as typeof fetch,
  });
  const worn = await flairs.listWornFlairs(WEARER);
  assert.deepEqual(worn, [
    { issuer: ISSUER, def: DEF, name: "Skytess-Pilot", policy: "open" },
  ]);
});

test("listWornFlairs carries imageCid and drops a mismatched-image badge", async () => {
  const matchingBadgeList = {
    match: "listRecords",
    body: {
      records: [
        {
          uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
          value: {
            issuer: ISSUER,
            def: DEF,
            image: IMAGE_CID,
            createdAt: "2026-01-01T00:00:00Z",
          },
        },
      ],
    },
  };
  const matching = createFlairs({
    fetch: fakeFetch([matchingBadgeList, defRouteWithImage(IMAGE_CID)]),
  });
  assert.deepEqual(await matching.listWornFlairs(WEARER), [
    { issuer: ISSUER, def: DEF, name: "Skytess-Pilot", policy: "open", imageCid: IMAGE_CID },
  ]);

  const mismatchedBadgeList = {
    match: "listRecords",
    body: {
      records: [
        {
          uri: `at://${WEARER}/at.tessera.flair.badge/${ISSUER}:${DEF}`,
          value: {
            issuer: ISSUER,
            def: DEF,
            image: "bafyother999",
            createdAt: "2026-01-01T00:00:00Z",
          },
        },
      ],
    },
  };
  const mismatched = createFlairs({
    fetch: fakeFetch([mismatchedBadgeList, defRouteWithImage(IMAGE_CID)]),
  });
  assert.deepEqual(await mismatched.listWornFlairs(WEARER), []);
});
