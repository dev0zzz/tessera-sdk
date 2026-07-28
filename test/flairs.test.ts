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
