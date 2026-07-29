/**
 * @tesseraat/sdk/radicle/unlock — browser-side unlocking of a Radicle identity.
 *
 * Separate entry point from ./radicle because this half only runs in a browser:
 * the seed is wrapped with a key derived from a WebAuthn PRF evaluation, and a
 * PRF evaluation needs a passkey ceremony. That ceremony is bound to the RP ID
 * the passkey was created with, so **only a page served from that origin can
 * perform it** — not a CLI, not localhost, not a library on its own. This
 * module is what such a page calls; the page itself is only the stage the
 * browser insists on.
 *
 * Nothing here talks to a private API. The ciphertext lives in a PUBLIC record
 * (`at.tessera.radicle.key`), because it is worthless without the passkey.
 */
import {
  RADICLE_HKDF_INFO_LABEL,
  RADICLE_KEY_COLLECTION,
  RADICLE_KEYSTORE_INFO_LABEL,
  RADICLE_PRF_SALT_LABEL,
  nidFromPublicKey,
  publicKeyFromSeed,
} from "./index.js";

export type RadicleKeyCopy = {
  credentialId: string;
  prfSalt: string;
  iv: string;
  ciphertext: string;
};

export type RadicleKeyRecord = {
  nid: string;
  keys: RadicleKeyCopy[];
};

export class RadicleNoIdentityError extends Error {
  constructor() {
    super("This account has no Radicle identity yet");
  }
}

export class RadiclePrfUnsupportedError extends Error {
  constructor() {
    super("This passkey does not support the PRF extension");
  }
}

export class RadicleNoCopyError extends Error {
  constructor() {
    super("The passkey you used holds no copy of this Radicle key");
  }
}

/** Reads the public key record for a DID. Returns null when there is none. */
export async function fetchRadicleKeyRecord(options: {
  did: string;
  pds: string;
  signal?: AbortSignal;
}): Promise<RadicleKeyRecord | null> {
  const url =
    `${options.pds}/xrpc/com.atproto.repo.getRecord` +
    `?repo=${encodeURIComponent(options.did)}` +
    `&collection=${RADICLE_KEY_COLLECTION}&rkey=self`;
  const res = await fetch(url, { signal: options.signal });
  if (!res.ok) return null;
  const data = (await res.json()) as { value?: Partial<RadicleKeyRecord> };
  const v = data.value;
  if (!v || typeof v.nid !== "string" || !Array.isArray(v.keys)) return null;
  if (v.keys.length === 0) return null; // emptied record — the identity is dead
  return { nid: v.nid, keys: v.keys as RadicleKeyCopy[] };
}

export type UnlockedRadicleIdentity = {
  /** raw 32-byte Ed25519 seed — the caller must zero it when done */
  seed: Uint8Array;
  /** derived from the NID in the record, not taken from it */
  nid: string;
  /** passphrase for the on-disk keystore, derived, never stored */
  keystorePassphrase: string;
};

/**
 * Prompts for a passkey and returns the decrypted Radicle seed together with
 * the passphrase that should protect it once it is written to disk.
 *
 * Both secrets come from ONE ceremony and one PRF secret, separated by HKDF
 * labels — so the file a caller writes is inert without a passkey, and no
 * passphrase has to be stored anywhere for that to hold.
 */
export async function unlockRadicleIdentity(options: {
  did: string;
  rpId: string;
  pds: string;
  /** pass a record you already have, to avoid a second fetch */
  record?: RadicleKeyRecord | null;
  signal?: AbortSignal;
}): Promise<UnlockedRadicleIdentity> {
  const record =
    options.record ??
    (await fetchRadicleKeyRecord({
      did: options.did,
      pds: options.pds,
      signal: options.signal,
    }));
  if (!record) throw new RadicleNoIdentityError();

  const salt = await labelSalt(RADICLE_PRF_SALT_LABEL);
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: options.rpId,
      userVerification: "preferred",
      // Only the passkeys that actually hold a copy — otherwise the user can
      // pick one that cannot decrypt and gets a confusing failure at the end.
      allowCredentials: record.keys.map((k) => ({
        type: "public-key" as const,
        id: fromBase64Url(k.credentialId),
      })),
      extensions: {
        prf: { eval: { first: salt } },
      } as AuthenticationExtensionsClientInputs,
    },
    signal: options.signal,
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error("Passkey assertion was cancelled");

  const results = credential.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const secret = results.prf?.results?.first;
  if (!secret) throw new RadiclePrfUnsupportedError();

  const credentialId = toBase64Url(new Uint8Array(credential.rawId));
  const copy = record.keys.find((k) => k.credentialId === credentialId);
  if (!copy) throw new RadicleNoCopyError();

  const aesKey = await deriveAesKey(secret, RADICLE_HKDF_INFO_LABEL);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(copy.iv) as BufferSource },
    aesKey,
    fromBase64Url(copy.ciphertext) as BufferSource,
  );
  const seed = new Uint8Array(plain);
  if (seed.length !== 32) {
    seed.fill(0);
    throw new Error("The decrypted key is not a 32-byte Ed25519 seed");
  }

  // Derive the NID from the SEED, and check the record agrees. A mismatch
  // means the record and the ciphertext disagree about which identity this
  // is — writing that to disk would give the user a node nobody expects.
  const nid = nidFromPublicKey(publicKeyFromSeed(seed));
  if (nid !== record.nid) {
    seed.fill(0);
    throw new Error(
      `The decrypted key is ${nid}, but the record claims ${record.nid}`,
    );
  }

  return {
    seed,
    nid,
    keystorePassphrase: await derivePassphrase(secret),
  };
}

// ---------------------------------------------------------------------------

async function labelSalt(label: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(label) as BufferSource,
  );
  return new Uint8Array(digest);
}

async function deriveAesKey(
  prfSecret: ArrayBuffer,
  info: string,
): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey("raw", prfSecret, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(info) as BufferSource,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function derivePassphrase(prfSecret: ArrayBuffer): Promise<string> {
  const hkdfKey = await crypto.subtle.importKey("raw", prfSecret, "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(RADICLE_KEYSTORE_INFO_LABEL) as BufferSource,
    },
    hkdfKey,
    256,
  );
  return toBase64Url(new Uint8Array(bits));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
