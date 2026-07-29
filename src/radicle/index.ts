/**
 * @tesseraat/sdk/radicle — the one implementation of Radicle node identity.
 *
 * Isomorphic and dependency-light (only @noble), so the same code runs in the
 * browser (minting an identity during sign-up or from settings), in the PDS
 * fork (verifying before it writes a public binding) and in the CLI (writing
 * the key to disk for `rad`). Before this module those four call sites each
 * carried their own copy with a "keep in sync with …" comment — which is a
 * promise no comment can keep for hand-rolled signature parsing.
 *
 * Three things live here:
 *
 *  - **NID** — a Radicle node id is multibase base58btc of multicodec
 *    ed25519-pub (`0xed 0x01` + the 32-byte key), exactly like `did:key`. The
 *    NID *is* the public key, so a signature that verifies against it proves
 *    control of that node.
 *  - **linkSig** — an armored OpenSSH SSHSIG over
 *    `at.tessera.radicle.link.v1:<did>` in namespace `at.tessera.radicle`.
 *    Byte-identical to `ssh-keygen -Y sign`, and verified byte-strictly, so a
 *    browser-minted identity and a CLI-brought one are indistinguishable.
 *  - **OpenSSH key file** — the format `rad` reads from
 *    `$RAD_HOME/keys/radicle`, so an identity kept in the passkey vault can be
 *    materialised on a machine when the user wants to work locally.
 *
 * Domain-separation labels are part of the on-disk/on-network contract:
 * changing one breaks every existing identity. Add a v2, never edit.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { utf8ToBytes } from "@noble/hashes/utils";

/** WebAuthn PRF salt label. Distinct from the wallet's on purpose: unlocking a
 *  Radicle key must never yield material that also opens the wallet. */
export const RADICLE_PRF_SALT_LABEL = "at.tessera.radicle.prf.v1";
/** HKDF info label for the AES-GCM key that wraps the seed. */
export const RADICLE_HKDF_INFO_LABEL = "at.tessera.radicle.enc.v1";
/**
 * HKDF info label for the passphrase that encrypts the ON-DISK keystore.
 *
 * A separate label so the disk passphrase can never decrypt the vault
 * ciphertext, and vice versa. Deriving it from the passkey rather than asking
 * for one is the point: there is then no passphrase to store, remember or
 * steal — the key file is inert without a passkey ceremony, which is the
 * whole security property this buys.
 */
export const RADICLE_KEYSTORE_INFO_LABEL = "at.tessera.radicle.keystore.v1";
export const RADICLE_LINK_NAMESPACE = "at.tessera.radicle";

export const RADICLE_KEY_COLLECTION = "at.tessera.radicle.key";
export const RADICLE_IDENTITY_COLLECTION = "at.tessera.radicle.identity";
export const RADICLE_REPO_COLLECTION = "at.tessera.radicle.repo";

/** The message a linkSig signs. */
export function radicleLinkMessage(did: string): string {
  return `at.tessera.radicle.link.v1:${did}`;
}

// ---------------------------------------------------------------------------
// NID
// ---------------------------------------------------------------------------

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = new Map([...B58].map((c, i) => [c, i] as const));

function base58Encode(data: Uint8Array): string {
  const digits: number[] = [];
  for (const byte of data) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  for (const byte of data) {
    if (byte !== 0) break;
    digits.push(0);
  }
  let out = "";
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

function base58Decode(s: string): Uint8Array {
  const bytes: number[] = [];
  for (const c of s) {
    const v = B58_MAP.get(c);
    if (v === undefined) throw new Error("invalid base58 character");
    let carry = v;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i] * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

/** `z` + base58btc(0xed 0x01 || pubkey) — what `rad node status` prints. */
export function nidFromPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("expected a 32-byte Ed25519 key");
  const prefixed = new Uint8Array(34);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return "z" + base58Encode(prefixed);
}

/** Decodes a NID to the raw 32-byte Ed25519 public key, or null. */
export function nidToEd25519(nid: string): Uint8Array | null {
  // Length cap BEFORE the O(n²) decode: this runs on foreign record data
  // during public profile reads, where an uncapped input would stall the
  // event loop for minutes.
  if (!nid.startsWith("z") || nid.length > 64) return null;
  let bytes: Uint8Array;
  try {
    bytes = base58Decode(nid.slice(1));
  } catch {
    return null;
  }
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) return null;
  return bytes.subarray(2);
}

export function isValidNid(nid: string): boolean {
  return nidToEd25519(nid) !== null;
}

/** rad:z… — charset and length checks keep garbage out of rkeys and URLs. */
export function isValidRid(rid: string): boolean {
  return /^rad:z[1-9A-HJ-NP-Za-km-z]{20,50}$/.test(rid);
}

// ---------------------------------------------------------------------------
// SSHSIG (OpenSSH PROTOCOL.sshsig)
// ---------------------------------------------------------------------------

function sshString(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + data.length);
  new DataView(out.buffer).setUint32(0, data.length);
  out.set(data, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function readString(buf: Uint8Array, off: number): [Uint8Array, number] {
  if (off + 4 > buf.length) throw new Error("truncated ssh string");
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const len = view.getUint32(off);
  const start = off + 4;
  const end = start + len;
  if (end > buf.length) throw new Error("truncated ssh string");
  return [buf.subarray(start, end), end];
}

const SSH_ED25519 = utf8ToBytes("ssh-ed25519");
const SSHSIG_MAGIC = utf8ToBytes("SSHSIG");
const HASH_ALG = utf8ToBytes("sha512");
const EMPTY = new Uint8Array(0);

/** The exact byte string OpenSSH signs (sshsig_wrap_sign). */
function sshsigSignedData(namespace: Uint8Array, digest: Uint8Array): Uint8Array {
  return concat(
    SSHSIG_MAGIC,
    sshString(namespace),
    sshString(EMPTY),
    sshString(HASH_ALG),
    sshString(digest),
  );
}

/**
 * Produces the armored signature `ssh-keygen -Y sign -n at.tessera.radicle`
 * would produce for the same key and message — byte for byte.
 */
export function signLinkMessage(seed: Uint8Array, did: string): string {
  const publicKey = ed25519.getPublicKey(seed);
  const namespace = utf8ToBytes(RADICLE_LINK_NAMESPACE);
  const digest = sha512(utf8ToBytes(radicleLinkMessage(did)));
  const rawSig = ed25519.sign(sshsigSignedData(namespace, digest), seed);

  const version = new Uint8Array(4);
  new DataView(version.buffer).setUint32(0, 1);
  const blob = concat(
    SSHSIG_MAGIC,
    version,
    sshString(concat(sshString(SSH_ED25519), sshString(publicKey))),
    sshString(namespace),
    sshString(EMPTY),
    sshString(HASH_ALG),
    sshString(concat(sshString(SSH_ED25519), sshString(rawSig))),
  );
  return armor(blob, "SSH SIGNATURE");
}

/**
 * Verifies an armored SSHSIG over `message` in the Radicle namespace, and
 * requires the signing key to be exactly `expectedPubkey`.
 *
 * Strict on purpose — every relaxation below was a finding in review:
 * exactly one armor block, base64 charset only, no trailing data at any of the
 * three nesting levels, Ed25519 only, size capped before decoding. A verifier
 * that accepts what `ssh-keygen -Y verify` rejects is a parser differential,
 * and this signature is the sole proof behind a public identity claim.
 */
export function verifyLinkSig(
  armored: string,
  message: string,
  expectedPubkey: Uint8Array,
): boolean {
  try {
    if (armored.length > 4096) return false;
    const m = armored
      .trim()
      .match(/^-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----$/);
    if (!m) return false;
    const body = m[1].replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) return false;
    const blob = fromBase64(body);

    if (asciiOf(blob.subarray(0, 6)) !== "SSHSIG") return false;
    const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
    if (view.getUint32(6) !== 1) return false;

    const [pubkeyBlob, o1] = readString(blob, 10);
    const [namespace, o2] = readString(blob, o1);
    const [reserved, o3] = readString(blob, o2);
    const [hashAlg, o4] = readString(blob, o3);
    const [sigBlob, end] = readString(blob, o4);
    if (end !== blob.length) return false;
    if (asciiOf(namespace) !== RADICLE_LINK_NAMESPACE) return false;

    const [keyType, p1] = readString(pubkeyBlob, 0);
    const [rawKey, pEnd] = readString(pubkeyBlob, p1);
    if (pEnd !== pubkeyBlob.length) return false;
    if (asciiOf(keyType) !== "ssh-ed25519" || rawKey.length !== 32) return false;
    if (!equalBytes(rawKey, expectedPubkey)) return false;

    const [sigType, s1] = readString(sigBlob, 0);
    const [rawSig, sEnd] = readString(sigBlob, s1);
    if (sEnd !== sigBlob.length) return false;
    if (asciiOf(sigType) !== "ssh-ed25519" || rawSig.length !== 64) return false;
    if (asciiOf(hashAlg) !== "sha512") return false;

    const digest = sha512(utf8ToBytes(message));
    // `reserved` is signed over, so it must go in as received.
    const signedData = concat(
      SSHSIG_MAGIC,
      sshString(namespace),
      sshString(reserved),
      sshString(hashAlg),
      sshString(digest),
    );
    return ed25519.verify(rawSig, signedData, rawKey);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// OpenSSH private key file — what `rad` reads from $RAD_HOME/keys/radicle
// ---------------------------------------------------------------------------

const OPENSSH_MAGIC = utf8ToBytes("openssh-key-v1\0");
const NONE = utf8ToBytes("none");

/**
 * Encodes an Ed25519 seed as an UNENCRYPTED OpenSSH private key, the format
 * `rad` expects (an empty passphrase yields exactly this). The caller is
 * responsible for writing it with 0600 — this is the plaintext node key.
 */
export function toOpenSshPrivateKey(seed: Uint8Array, comment = "radicle"): string {
  const publicKey = ed25519.getPublicKey(seed);
  const pubBlob = concat(sshString(SSH_ED25519), sshString(publicKey));
  // check bytes must match; any value works, OpenSSH uses them to detect a
  // wrong passphrase after decryption.
  const check = new Uint8Array(4);
  new DataView(check.buffer).setUint32(0, 0x5445_5353);
  const privateSection = concat(
    check,
    check,
    sshString(SSH_ED25519),
    sshString(publicKey),
    sshString(concat(seed, publicKey)), // OpenSSH stores seed||public as the private key
    sshString(utf8ToBytes(comment)),
  );
  // Pad to a multiple of the cipher block size (8 for "none") with 1,2,3…
  // An already-aligned section gets NO padding — OpenSSH's loop is
  // `while (len % blocksize)`, so forcing a byte here would produce a file
  // real ssh-keygen rejects.
  const padded = new Uint8Array(Math.ceil(privateSection.length / 8) * 8);
  padded.set(privateSection);
  for (let i = privateSection.length, n = 1; i < padded.length; i++, n++) {
    padded[i] = n;
  }

  const blob = concat(
    OPENSSH_MAGIC,
    sshString(NONE), // ciphername
    sshString(NONE), // kdfname
    sshString(EMPTY), // kdfoptions
    uint32(1), // number of keys
    sshString(pubBlob),
    sshString(padded),
  );
  return armor(blob, "OPENSSH PRIVATE KEY");
}

/** The matching `radicle.pub` line. */
export function toOpenSshPublicKey(seed: Uint8Array, comment = "radicle"): string {
  const publicKey = ed25519.getPublicKey(seed);
  const blob = concat(sshString(SSH_ED25519), sshString(publicKey));
  return `ssh-ed25519 ${toBase64(blob)} ${comment}\n`;
}

export type RadicleDevice = {
  nid: string;
  linkSig: string;
  name: string;
  addedAt: string;
};

/**
 * Mints a node identity for THIS machine and the proof that it belongs to a
 * DID. The seed is returned to the caller to write locally and never travels:
 * what goes to the account is `device`, which is entirely public.
 *
 * This is the shape that makes "I never hand over my secrets" literally true —
 * there is no secret to hand over, only a claim and a signature over it.
 */
export function createDeviceIdentity(options: {
  did: string;
  name: string;
  /** supply a seed to adopt an existing local key instead of minting one */
  seed?: Uint8Array;
  now?: Date;
}): { seed: Uint8Array; device: RadicleDevice } {
  const seed = options.seed ?? ed25519.utils.randomPrivateKey();
  const nid = nidFromPublicKey(ed25519.getPublicKey(seed));
  return {
    seed,
    device: {
      nid,
      linkSig: signLinkMessage(seed, options.did),
      name: options.name.slice(0, 64),
      addedAt: (options.now ?? new Date()).toISOString(),
    },
  };
}

/**
 * Filters a device list down to the entries whose signature actually proves
 * the claim, for THIS did. Anything unproven is dropped rather than shown —
 * the record is writable by the account owner through any client, so an
 * unverified entry is a claim, not a binding.
 *
 * Duplicate NIDs collapse to the first verified occurrence, so a second entry
 * cannot shadow or double-count a device.
 */
export function verifiedDevices(
  did: string,
  devices: readonly unknown[] | undefined,
): RadicleDevice[] {
  const out: RadicleDevice[] = [];
  const seen = new Set<string>();
  for (const raw of devices ?? []) {
    const d = raw as Partial<RadicleDevice> | null;
    if (
      !d ||
      typeof d.nid !== "string" ||
      typeof d.linkSig !== "string" ||
      typeof d.name !== "string"
    ) {
      continue;
    }
    if (seen.has(d.nid)) continue;
    const pubkey = nidToEd25519(d.nid);
    if (!pubkey) continue;
    if (!verifyLinkSig(d.linkSig, radicleLinkMessage(did), pubkey)) continue;
    seen.add(d.nid);
    out.push({
      nid: d.nid,
      linkSig: d.linkSig,
      name: d.name.slice(0, 64),
      addedAt: typeof d.addedAt === "string" ? d.addedAt : "",
    });
  }
  return out;
}

/**
 * Derives the passphrase that protects the on-disk keystore from the passkey's
 * PRF secret. Returns base64url of 32 bytes — long enough that the keystore's
 * own KDF is not the weak link, and printable so it can be handed to
 * `ssh-keygen`/`RAD_PASSPHRASE`.
 *
 * Same input as the vault key, different HKDF label, so the two are
 * independent. Callers must never persist the result.
 */
export async function deriveKeystorePassphrase(
  prfSecret: ArrayBuffer,
): Promise<string> {
  const hkdfKey = await crypto.subtle.importKey("raw", prfSecret, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: utf8ToBytes(RADICLE_KEYSTORE_INFO_LABEL) as BufferSource,
    },
    hkdfKey,
    256,
  );
  return toBase64(new Uint8Array(bits))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Public key of a seed, for callers that only need the NID. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

// ---------------------------------------------------------------------------
// encoding helpers (isomorphic — no Buffer, no atob assumptions)
// ---------------------------------------------------------------------------

function uint32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n);
  return out;
}

function asciiOf(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return s;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function toBase64(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? "=" : B64[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? "=" : B64[b2 & 63];
  }
  return out;
}

export function fromBase64(s: string): Uint8Array {
  const clean = s.replace(/=+$/, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of clean) {
    const v = B64.indexOf(c);
    if (v < 0) throw new Error("invalid base64 character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out.subarray(0, o);
}

function armor(blob: Uint8Array, label: string): string {
  const lines = toBase64(blob).match(/.{1,70}/g) ?? [];
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`, ""].join("\n");
}
