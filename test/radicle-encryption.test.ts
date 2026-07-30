import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decryptCobText,
  decryptContent,
  deriveEncryptionKeypair,
  encryptCobText,
  encryptContent,
  isEncryptedCobText,
  newRepoKey,
  openSealed,
  sealTo,
} from "../dist/radicle/index.js";

const seedA = new Uint8Array(32).fill(1);
const seedB = new Uint8Array(32).fill(2);

test("device keypair is derived deterministically from the radicle seed", async () => {
  // The whole point of deriving instead of storing: the same backed-up key
  // always yields the same encryption key, so there is no second secret to
  // lose. If this were random, a restored machine could not decrypt anything.
  const first = await deriveEncryptionKeypair(seedA);
  const second = await deriveEncryptionKeypair(seedA);
  assert.deepEqual(first.secretKey, second.secretKey);
  assert.deepEqual(first.publicKey, second.publicKey);
});

test("different radicle seeds give different encryption keys", async () => {
  const a = await deriveEncryptionKeypair(seedA);
  const b = await deriveEncryptionKeypair(seedB);
  assert.notDeepEqual(a.publicKey, b.publicKey);
});

test("the encryption key is NOT the signing key", async () => {
  // Domain separation is the reason for the HKDF. If the derived secret equalled
  // the seed, we would be using one key for two primitives.
  const { secretKey } = await deriveEncryptionKeypair(seedA);
  assert.notDeepEqual(secretKey, seedA);
});

test("a delegate can unwrap the repo key sealed to them", async () => {
  const delegate = await deriveEncryptionKeypair(seedA);
  const repoKey = newRepoKey();
  const sealed = await sealTo(delegate.publicKey, repoKey);
  assert.deepEqual(await openSealed(delegate.secretKey, sealed), repoKey);
});

test("a non-delegate cannot unwrap it", async () => {
  // This is the security claim in one test: holding the ciphertext and being a
  // valid Tessera user is not enough — only the named recipient can open it.
  const delegate = await deriveEncryptionKeypair(seedA);
  const stranger = await deriveEncryptionKeypair(seedB);
  const sealed = await sealTo(delegate.publicKey, newRepoKey());
  await assert.rejects(() => openSealed(stranger.secretKey, sealed));
});

test("sealing the same key twice gives different blobs", async () => {
  // Ephemeral sender key per call — otherwise two delegates receiving the same
  // repo key would produce identical wrappers, which leaks that they hold the
  // same key.
  const delegate = await deriveEncryptionKeypair(seedA);
  const repoKey = newRepoKey();
  const one = await sealTo(delegate.publicKey, repoKey);
  const two = await sealTo(delegate.publicKey, repoKey);
  assert.notDeepEqual(one, two);
  // …and both still open.
  assert.deepEqual(await openSealed(delegate.secretKey, one), repoKey);
  assert.deepEqual(await openSealed(delegate.secretKey, two), repoKey);
});

test("a tampered sealed blob is rejected, not silently wrong", async () => {
  const delegate = await deriveEncryptionKeypair(seedA);
  const sealed = await sealTo(delegate.publicKey, newRepoKey());
  sealed[sealed.length - 1] ^= 0xff;
  await assert.rejects(() => openSealed(delegate.secretKey, sealed));
});

test("content encryption round-trips", async () => {
  const repoKey = newRepoKey();
  const plain = new TextEncoder().encode("const secret = 42;\n");
  const enc = await encryptContent(repoKey, plain, "src/index.ts");
  assert.deepEqual(await decryptContent(repoKey, enc), plain);
});

test("content encryption is deterministic — git would be unusable otherwise", async () => {
  // With a random nonce, every commit would re-encrypt every file and git would
  // show the whole tree as modified each time.
  const repoKey = newRepoKey();
  const plain = new TextEncoder().encode("unchanged file\n");
  const a = await encryptContent(repoKey, plain, "README.md");
  const b = await encryptContent(repoKey, plain, "README.md");
  assert.deepEqual(a, b);
});

test("the same bytes at a different path encrypt differently", async () => {
  // Limits the leak of determinism to "same content at the same path" instead
  // of "same content anywhere in the repo".
  const repoKey = newRepoKey();
  const plain = new TextEncoder().encode("same bytes\n");
  const a = await encryptContent(repoKey, plain, "a.txt");
  const b = await encryptContent(repoKey, plain, "b.txt");
  assert.notDeepEqual(a, b);
});

test("the path is unambiguously separated from the content", async () => {
  // Without a separator, ("ab", "c") and ("a", "bc") would share a nonce.
  const repoKey = newRepoKey();
  const one = await encryptContent(repoKey, new TextEncoder().encode("c"), "ab");
  const two = await encryptContent(repoKey, new TextEncoder().encode("bc"), "a");
  assert.notDeepEqual(one.subarray(0, 12), two.subarray(0, 12));
});

test("the wrong repo key cannot read content", async () => {
  const enc = await encryptContent(newRepoKey(), new TextEncoder().encode("x"), "f");
  await assert.rejects(() => decryptContent(newRepoKey(), enc));
});

test("COB text round-trips and is marked as encrypted", async () => {
  // COBs cannot be covered by a git filter: clean/smudge runs between working
  // tree and index, while `rad issue open` writes into the object database
  // directly. So the text has to be ciphertext before rad ever sees it.
  const repoKey = newRepoKey();
  const enc = await encryptCobText(repoKey, "Kunde Müller will Rabattlogik ändern");
  assert.ok(isEncryptedCobText(enc));
  assert.ok(!enc.includes("Müller"), "plaintext must not survive in the armour");
  assert.equal(await decryptCobText(repoKey, enc), "Kunde Müller will Rabattlogik ändern");
});

test("COB text uses a random nonce — identical comments must not look identical", async () => {
  // Unlike file content there is no diff to keep stable here, so two people
  // writing "lgtm" should not be recognisable as having written the same thing.
  const repoKey = newRepoKey();
  const a = await encryptCobText(repoKey, "lgtm");
  const b = await encryptCobText(repoKey, "lgtm");
  assert.notEqual(a, b);
});

test("plaintext COB text passes through untouched", async () => {
  // A repository can hold both; refusing to show older plaintext would be worse
  // than showing it.
  const repoKey = newRepoKey();
  assert.equal(await decryptCobText(repoKey, "a normal issue title"), "a normal issue title");
  assert.ok(!isEncryptedCobText("a normal issue title"));
});

test("COB text survives multi-byte characters and newlines", async () => {
  const repoKey = newRepoKey();
  const text = "Zeile 1\nZeile 2 — mit Gedankenstrich, Ümläuten und 😀\n";
  assert.equal(await decryptCobText(repoKey, await encryptCobText(repoKey, text)), text);
});

test("a tampered COB blob is rejected", async () => {
  const repoKey = newRepoKey();
  const enc = await encryptCobText(repoKey, "secret");
  const broken = enc.slice(0, -2) + (enc.endsWith("A=") ? "B=" : "A=");
  await assert.rejects(() => decryptCobText(repoKey, broken));
});

test("an empty file encrypts and decrypts", async () => {
  const repoKey = newRepoKey();
  const enc = await encryptContent(repoKey, new Uint8Array(0), "empty");
  assert.deepEqual(await decryptContent(repoKey, enc), new Uint8Array(0));
});

test("a wrong-sized seed is refused rather than silently padded", async () => {
  await assert.rejects(() => deriveEncryptionKeypair(new Uint8Array(16)));
});

test("a written key file reads back to the same seed", async () => {
  // Round-trip against our own writer AND against ssh-keygen's opinion of the
  // file, so this cannot drift into a format only we accept.
  const { seedFromOpenSshPrivateKey, toOpenSshPrivateKey, toOpenSshPublicKey } = await import(
    "../dist/radicle/index.js"
  );
  const seed = new Uint8Array(32).fill(7);
  const pem = toOpenSshPrivateKey(seed, "roundtrip");
  assert.deepEqual(seedFromOpenSshPrivateKey(pem), seed);

  // And the derived encryption key matches what the seed gives directly.
  const fromFile = await deriveEncryptionKeypair(seedFromOpenSshPrivateKey(pem));
  const fromSeed = await deriveEncryptionKeypair(seed);
  assert.deepEqual(fromFile.publicKey, fromSeed.publicKey);
  assert.ok(toOpenSshPublicKey(seed).startsWith("ssh-ed25519 "));
});

test("a passphrase-protected key file is refused with a usable message", async () => {
  const { seedFromOpenSshPrivateKey } = await import("../dist/radicle/index.js");
  // A real encrypted header: cipher aes256-ctr, kdf bcrypt.
  const enc =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
    Buffer.from(
      Buffer.concat([
        Buffer.from("openssh-key-v1\0", "binary"),
        Buffer.from([0, 0, 0, 10]), Buffer.from("aes256-ctr"),
        Buffer.from([0, 0, 0, 6]), Buffer.from("bcrypt"),
        Buffer.from([0, 0, 0, 0]),
      ]),
    ).toString("base64") +
    "\n-----END OPENSSH PRIVATE KEY-----\n";
  assert.throws(() => seedFromOpenSshPrivateKey(enc), /passphrase-protected/);
});

test("garbage is rejected rather than yielding a wrong seed", async () => {
  const { seedFromOpenSshPrivateKey } = await import("../dist/radicle/index.js");
  assert.throws(() => seedFromOpenSshPrivateKey("not a key at all"));
});

test("a key file written by real ssh-keygen reads back correctly", async () => {
  // The one that matters: our writer and reader could agree on a format that
  // OpenSSH does not use. This starts from ssh-keygen's own output.
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, readFileSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { seedFromOpenSshPrivateKey, nidFromPublicKey } = await import(
    "../dist/radicle/index.js"
  );
  const { ed25519 } = await import("@noble/curves/ed25519");

  const dir = mkdtempSync(join(tmpdir(), "sdk-sshkey-"));
  try {
    const key = join(dir, "id");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", key]);
    const seed = seedFromOpenSshPrivateKey(readFileSync(key, "utf8"));
    assert.equal(seed.length, 32);

    // The public key we derive must equal the one ssh-keygen printed. The .pub
    // line holds an SSH blob — string("ssh-ed25519") ‖ string(key) — so the raw
    // key starts at 4+11+4 = 19.
    const blob = Buffer.from(readFileSync(`${key}.pub`, "utf8").split(/\s+/)[1], "base64");
    assert.deepEqual(
      new Uint8Array(blob.subarray(19, 51)),
      ed25519.getPublicKey(seed),
      "derived public key must match ssh-keygen's",
    );
    assert.ok(nidFromPublicKey(ed25519.getPublicKey(seed)).startsWith("z"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
