import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import {
  RADICLE_LINK_NAMESPACE,
  deriveKeystorePassphrase,
  isValidNid,
  isValidRid,
  nidFromPublicKey,
  nidToEd25519,
  publicKeyFromSeed,
  radicleLinkMessage,
  signLinkMessage,
  toOpenSshPrivateKey,
  toOpenSshPublicKey,
  verifyLinkSig,
} from "../dist/radicle/index.js";

// These tests exist because every property below is load-bearing for a
// PUBLIC identity claim, and all of it is hand-rolled binary format work.
// The negative cases matter most: they are what a later "simplification"
// would quietly remove.

const DID = "did:plc:t7k4swni6fqt3okcjj5pqitt";

function tmp(): string {
  return mkdtempSync(join(tmpdir(), "tessera-radicle-"));
}

test("NID round-trips for many keys, and is 48 chars", () => {
  for (let i = 0; i < 500; i++) {
    const seed = ed25519.utils.randomPrivateKey();
    const pub = publicKeyFromSeed(seed);
    const nid = nidFromPublicKey(pub);
    assert.equal(nid.length, 48);
    assert.ok(isValidNid(nid));
    assert.deepEqual(nidToEd25519(nid), pub);
  }
});

test("NID matches the encoding the seed node prints", () => {
  // Captured from `rad node status` on seed.tessera.at.
  const nid = "z6MkpActjmdXiig55Qj4NkW1EbTbTTgkojPZ2BPcdQz3ViPw";
  const pub = nidToEd25519(nid);
  assert.ok(pub && pub.length === 32);
  assert.equal(nidFromPublicKey(pub), nid);
});

test("NID rejects garbage without doing quadratic work", () => {
  assert.equal(nidToEd25519(""), null);
  assert.equal(nidToEd25519("6MkpAc"), null, "missing z prefix");
  assert.equal(nidToEd25519("z" + "1".repeat(200)), null, "over the length cap");
  assert.equal(nidToEd25519("z0OIl"), null, "not base58 alphabet");
  // A did:key for a NON-ed25519 curve must not decode as one.
  assert.equal(nidToEd25519("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"), null);
});

test("RID validation keeps traversal and stray input out of rkeys", () => {
  assert.ok(isValidRid("rad:z2mwUoXhiRGLsu7qAToHtLDBwfD6i"));
  assert.ok(!isValidRid("z2mwUoXhiRGLsu7qAToHtLDBwfD6i"), "prefix required");
  assert.ok(!isValidRid("rad:z../../etc/passwd"));
  assert.ok(!isValidRid("rad:z2mwUoXhiRGLsu7qAToHtLDBwfD6i\n"), "no trailing newline");
  assert.ok(!isValidRid("rad:z" + "1".repeat(80)), "length capped");
});

test("a signature verifies, and is bound to both the DID and the key", () => {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = publicKeyFromSeed(seed);
  const sig = signLinkMessage(seed, DID);

  assert.ok(verifyLinkSig(sig, radicleLinkMessage(DID), pub));
  assert.ok(
    !verifyLinkSig(sig, radicleLinkMessage("did:plc:someoneelse"), pub),
    "a signature for one DID must not verify for another",
  );
  const other = publicKeyFromSeed(ed25519.utils.randomPrivateKey());
  assert.ok(!verifyLinkSig(sig, radicleLinkMessage(DID), other), "wrong key");
});

test("verification is strict about the armored form", () => {
  const seed = ed25519.utils.randomPrivateKey();
  const pub = publicKeyFromSeed(seed);
  const sig = signLinkMessage(seed, DID);
  const msg = radicleLinkMessage(DID);
  const ok = (s: string) => verifyLinkSig(s, msg, pub);

  assert.ok(!ok(sig + sig), "two armor blocks");
  assert.ok(!ok("preamble\n" + sig), "prose before the block");
  assert.ok(!ok(sig.replace("-----BEGIN SSH SIGNATURE-----\n", "")), "no header");
  assert.ok(!ok("-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----"), "not base64");
  assert.ok(!ok("x".repeat(5000)), "over the size cap");
  // Flipping one signature byte must fail.
  const lines = sig.split("\n");
  const body = lines.slice(1, -2).join("");
  const flipped = body.slice(0, 100) + (body[100] === "A" ? "B" : "A") + body.slice(101);
  assert.ok(
    !ok(["-----BEGIN SSH SIGNATURE-----", flipped, "-----END SSH SIGNATURE-----", ""].join("\n")),
    "tampered signature",
  );
});

test("real ssh-keygen accepts our signature", () => {
  const dir = tmp();
  try {
    const seed = ed25519.utils.randomPrivateKey();
    const sig = signLinkMessage(seed, DID);
    writeFileSync(join(dir, "sig"), sig);
    writeFileSync(
      join(dir, "allowed"),
      `tessera ${toOpenSshPublicKey(seed, "tessera").trim()}\n`,
    );
    const out = execFileSync(
      "ssh-keygen",
      ["-Y", "verify", "-f", join(dir, "allowed"), "-I", "tessera",
       "-n", RADICLE_LINK_NAMESPACE, "-s", join(dir, "sig")],
      { input: radicleLinkMessage(DID), encoding: "utf8" },
    );
    assert.match(out, /Good "at\.tessera\.radicle" signature/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("real ssh-keygen reads the private key file we write", () => {
  const dir = tmp();
  try {
    const seed = ed25519.utils.randomPrivateKey();
    const keyPath = join(dir, "radicle");
    writeFileSync(keyPath, toOpenSshPrivateKey(seed, "tessera"));
    chmodSync(keyPath, 0o600);

    // ssh-keygen -y derives the public key from the private one. If our
    // encoding were wrong (padding, check bytes, key order) this fails.
    const derived = execFileSync("ssh-keygen", ["-y", "-f", keyPath], {
      encoding: "utf8",
    }).trim();
    const expected = toOpenSshPublicKey(seed, "tessera").trim();
    assert.equal(
      derived.split(" ").slice(0, 2).join(" "),
      expected.split(" ").slice(0, 2).join(" "),
    );

    // And the fingerprint must match a key ssh-keygen imports cleanly.
    const fp = execFileSync("ssh-keygen", ["-l", "-f", keyPath], { encoding: "utf8" });
    assert.match(fp, /ED25519/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the key file we write round-trips through a real signing tool", () => {
  const dir = tmp();
  try {
    const seed = ed25519.utils.randomPrivateKey();
    const keyPath = join(dir, "radicle");
    writeFileSync(keyPath, toOpenSshPrivateKey(seed));
    chmodSync(keyPath, 0o600);
    writeFileSync(join(dir, "radicle.pub"), toOpenSshPublicKey(seed));

    // ssh-keygen signs with the file; OUR verifier must accept it. This is the
    // real interop direction for `rad`: a key we materialised, used by an
    // external tool, verified by us.
    const sigPath = join(dir, "out.sig");
    execFileSync(
      "sh",
      ["-c",
       `printf '%s' "$1" | ssh-keygen -Y sign -f "$2" -n ${RADICLE_LINK_NAMESPACE} - > "$3"`,
       "sh", radicleLinkMessage(DID), keyPath, sigPath],
      { encoding: "utf8" },
    );
    const sig = readFileSync(sigPath, "utf8");
    assert.ok(verifyLinkSig(sig, radicleLinkMessage(DID), publicKeyFromSeed(seed)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the keystore passphrase is derived, deterministic and unstealable", async () => {
  const secret = new Uint8Array(32).fill(7).buffer;
  const a = await deriveKeystorePassphrase(secret);
  const b = await deriveKeystorePassphrase(secret);
  assert.equal(a, b, "same passkey secret must always yield the same passphrase");
  assert.match(a, /^[A-Za-z0-9_-]+$/, "must survive an argv/env round trip");
  assert.ok(a.length >= 40, "32 bytes of entropy, so the keystore KDF is not the weak link");

  const other = await deriveKeystorePassphrase(new Uint8Array(32).fill(8).buffer);
  assert.notEqual(a, other, "a different passkey must not open the same keystore");

  // The keystore passphrase must NOT be usable as the vault key and vice
  // versa — that separation is why one leaking does not imply the other.
  const vaultKey = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("at.tessera.radicle.enc.v1"),
    },
    await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]),
    256,
  );
  const asText = Buffer.from(vaultKey).toString("base64url");
  assert.notEqual(a, asText, "keystore passphrase and vault key must differ");
});
