/**
 * Encryption for private Radicle repositories.
 *
 * Radicle does not encrypt private repos at rest — its own FAQ says a seed on
 * the allow list can read the data, and that was confirmed by finding a canary
 * string in a node's storage in plaintext. For a garden hosting OTHER people's
 * private repos, that makes the operator a party you have to trust. This module
 * exists to remove them from that position.
 *
 * The arrangement, in one line: a repository key encrypts the content, and that
 * key is wrapped once per delegate — so being a delegate and being able to
 * decrypt become the same thing, and Radicle's access control becomes the
 * cryptographic one instead of sitting beside it.
 *
 * WHAT THIS DOES NOT HIDE (stated here so no caller has to guess): file names,
 * the directory tree, commit messages, node ids of participants, timing and
 * size. A seed has to understand git to replicate at all, so the structure
 * stays legible. Only content is ciphertext.
 *
 * Primitives are WebCrypto (HKDF, AES-256-GCM) plus @noble/curves for X25519 —
 * the same pair the rest of this SDK already uses, so this adds no dependency
 * and runs unchanged in a browser and in Node.
 */

import { x25519 } from "@noble/curves/ed25519";

/** Domain labels. Never reuse one for a second purpose. */
const LABEL_DEVICE_KEY = "at.tessera.radicle.enc.x25519.v1";
const LABEL_SEAL = "at.tessera.radicle.seal.v1";
const LABEL_CONTENT_NONCE = "at.tessera.radicle.content.nonce.v1";

const AES_KEY_BITS = 256;
const IV_BYTES = 12;
const X25519_BYTES = 32;

export type EncryptionKeypair = {
  /** X25519 public key — published in the identity record next to the NID. */
  publicKey: Uint8Array;
  /** X25519 secret key — derived on demand, never stored. */
  secretKey: Uint8Array;
};

async function hkdf(
  ikm: Uint8Array,
  info: string,
  salt: Uint8Array,
  bytes: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: new TextEncoder().encode(info),
    },
    key,
    bytes * 8,
  );
  return new Uint8Array(bits);
}

/**
 * The device's encryption keypair, derived from the Radicle key it already has.
 *
 * DERIVED, not converted. Ed25519 can be bent into X25519
 * (`crypto_sign_ed25519_pk_to_curve25519`), but using one key for both
 * signing and encryption is needless risk. An HKDF with its own label is clean
 * domain separation — and it costs nothing, because the result comes back
 * deterministically from a key that is already backed up. No second secret to
 * lose, no second backup to forget.
 */
export async function deriveEncryptionKeypair(
  radicleSeed: Uint8Array,
): Promise<EncryptionKeypair> {
  if (radicleSeed.length !== 32) {
    throw new Error("radicle seed must be 32 bytes");
  }
  const secretKey = await hkdf(
    radicleSeed,
    LABEL_DEVICE_KEY,
    new Uint8Array(0),
    X25519_BYTES,
  );
  return { secretKey, publicKey: x25519.getPublicKey(secretKey) };
}

/** A fresh repository key. This is what actually encrypts the content. */
export function newRepoKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function aesKey(raw: Uint8Array, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, usage);
}

/**
 * Seals `plaintext` so that only the holder of `recipientPublicKey` can open it.
 *
 * Anonymous sealed box: a throwaway keypair per call, so the sender is not
 * identifiable from the output and no sender key has to exist. Layout is
 * `ephemeralPublicKey(32) ‖ iv(12) ‖ ciphertext‖tag`.
 *
 * Both public keys go into the HKDF salt. Binding the derived key to the exact
 * pair stops a sealed blob from being replayed at a different recipient.
 */
export async function sealTo(
  recipientPublicKey: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  if (recipientPublicKey.length !== X25519_BYTES) {
    throw new Error("recipient public key must be 32 bytes");
  }
  const ephSecret = x25519.utils.randomPrivateKey();
  const ephPublic = x25519.getPublicKey(ephSecret);
  const shared = x25519.getSharedSecret(ephSecret, recipientPublicKey);

  const salt = new Uint8Array(X25519_BYTES * 2);
  salt.set(ephPublic, 0);
  salt.set(recipientPublicKey, X25519_BYTES);

  const raw = await hkdf(shared, LABEL_SEAL, salt, 32);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      await aesKey(raw, ["encrypt"]),
      plaintext as BufferSource,
    ),
  );

  const out = new Uint8Array(ephPublic.length + iv.length + ct.length);
  out.set(ephPublic, 0);
  out.set(iv, ephPublic.length);
  out.set(ct, ephPublic.length + iv.length);
  return out;
}

/** Opens what `sealTo` produced. Throws if it was not sealed to this key. */
export async function openSealed(
  recipientSecretKey: Uint8Array,
  sealed: Uint8Array,
): Promise<Uint8Array> {
  if (sealed.length < X25519_BYTES + IV_BYTES + 16) {
    throw new Error("sealed blob is too short");
  }
  const ephPublic = sealed.subarray(0, X25519_BYTES);
  const iv = sealed.subarray(X25519_BYTES, X25519_BYTES + IV_BYTES);
  const ct = sealed.subarray(X25519_BYTES + IV_BYTES);

  const recipientPublic = x25519.getPublicKey(recipientSecretKey);
  const shared = x25519.getSharedSecret(recipientSecretKey, ephPublic);

  const salt = new Uint8Array(X25519_BYTES * 2);
  salt.set(ephPublic, 0);
  salt.set(recipientPublic, X25519_BYTES);

  const raw = await hkdf(shared, LABEL_SEAL, salt, 32);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await aesKey(raw, ["decrypt"]),
    ct as BufferSource,
  );
  return new Uint8Array(plain);
}

/**
 * Encrypts repository content DETERMINISTICALLY: the same input always gives
 * the same output.
 *
 * This is not laziness, it is what makes git usable. With a random nonce every
 * commit would re-encrypt every file into something new, and git would report
 * the whole tree as modified on every single commit. git-crypt derives its
 * nonce from the plaintext for exactly this reason.
 *
 * THE PRICE, named plainly: identical content yields identical ciphertext, so
 * an observer — including the garden operator — can tell that two files are the
 * same, or that a file did not change between commits. What they cannot tell is
 * what it says.
 *
 * `context` (use the repo-relative path) is mixed into the nonce so the same
 * bytes at two paths do not collide, which keeps that leak to "same content at
 * the same path".
 *
 * Nonce is 12 bytes of HKDF output over key‖context‖plaintext. AES-GCM-SIV
 * would be the textbook primitive here, but WebCrypto does not offer it; this
 * construction is equivalent in effect for our purpose, with a birthday bound
 * around 2^48 distinct (path, content) pairs — far past any repository.
 */
export async function encryptContent(
  repoKey: Uint8Array,
  plaintext: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  const ctx = new TextEncoder().encode(context);
  const material = new Uint8Array(ctx.length + 1 + plaintext.length);
  material.set(ctx, 0);
  material[ctx.length] = 0x00; // separator, so ("ab","c") ≠ ("a","bc")
  material.set(plaintext, ctx.length + 1);

  const iv = await hkdf(repoKey, LABEL_CONTENT_NONCE, material, IV_BYTES);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      await aesKey(repoKey, ["encrypt"]),
      plaintext as BufferSource,
    ),
  );

  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv, 0);
  out.set(ct, IV_BYTES);
  return out;
}

/** Decrypts what `encryptContent` produced. */
export async function decryptContent(
  repoKey: Uint8Array,
  encrypted: Uint8Array,
): Promise<Uint8Array> {
  if (encrypted.length < IV_BYTES + 16) {
    throw new Error("encrypted content is too short");
  }
  const iv = encrypted.subarray(0, IV_BYTES);
  const ct = encrypted.subarray(IV_BYTES);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    await aesKey(repoKey, ["decrypt"]),
    ct as BufferSource,
  );
  return new Uint8Array(plain);
}

/**
 * Encrypts a COB text field (issue title, body, comment, review).
 *
 * COBs need their own path because a git filter cannot reach them: clean/smudge
 * runs between working tree and index, while `rad issue open` writes straight
 * into the object database. Measured, not assumed — issue text was found as a
 * plaintext blob under `refs/cobs/xyz.radicle.issue/…`. So the text has to be
 * ciphertext BEFORE it is handed to rad.
 *
 * Returns armoured text (`tsrenc1:<base64>`), because a COB field is a string
 * and has to survive as one. The marker lets a reader tell "encrypted" from
 * "someone wrote base64", and lets a future format change be recognised rather
 * than mis-decrypted.
 *
 * Uses a RANDOM nonce, unlike file content: there is no diff to keep stable
 * here, so identical comments should not be recognisable as identical.
 */
export async function encryptCobText(repoKey: Uint8Array, text: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      await aesKey(repoKey, ["encrypt"]),
      new TextEncoder().encode(text) as BufferSource,
    ),
  );
  const blob = new Uint8Array(IV_BYTES + ct.length);
  blob.set(iv, 0);
  blob.set(ct, IV_BYTES);
  return `tsrenc1:${toBase64(blob)}`;
}

/** True if `text` looks like output of `encryptCobText`. */
export function isEncryptedCobText(text: string): boolean {
  return text.startsWith("tsrenc1:");
}

/**
 * Decrypts a COB text field. Text that is not marked as encrypted is returned
 * unchanged — a repository can hold both, and refusing to display older
 * plaintext would be worse than showing it.
 */
export async function decryptCobText(repoKey: Uint8Array, text: string): Promise<string> {
  if (!isEncryptedCobText(text)) return text;
  const blob = fromBase64(text.slice("tsrenc1:".length));
  if (blob.length < IV_BYTES + 16) throw new Error("encrypted COB text is too short");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.subarray(0, IV_BYTES) as BufferSource },
    await aesKey(repoKey, ["decrypt"]),
    blob.subarray(IV_BYTES) as BufferSource,
  );
  return new TextDecoder().decode(plain);
}

// Base64 without a Buffer dependency, so this stays browser-safe.
function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
