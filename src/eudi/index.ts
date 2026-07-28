/**
 * @tesseraat/sdk/eudi — verify a state-signed OpenID4VP presentation (SD-JWT VC)
 * against an EU trust list and return the selectively-disclosed claims.
 *
 * Pure & stateless. Node-only. Peer/crypto dep: @sd-jwt/sd-jwt-vc (via ./sdjwt.js).
 */

import { defaultCredentialVerifier } from "./sdjwt.js";

export type EudiErrorCode =
  | "malformed"
  | "untrusted_issuer"
  | "bad_signature"
  | "expired"
  | "not_yet_valid"
  | "audience_mismatch"
  | "nonce_mismatch"
  | "missing_key_binding";

export class EudiVerificationError extends Error {
  readonly code: EudiErrorCode;
  constructor(message: string, code: EudiErrorCode) {
    super(message);
    this.name = "EudiVerificationError";
    this.code = code;
  }
}

export interface TrustAnchor {
  issuer: string;
  publicKeyJwk: JsonWebKey;
}

export interface CredentialContent {
  issuer: string;
  claims: Record<string, unknown>;
  notBefore?: number;
  expiresAt?: number;
  keyBindingAudience?: string;
  keyBindingNonce?: string;
  hasKeyBinding: boolean;
}

export type CredentialVerifier = (
  vpToken: string,
  resolveIssuerKey: (issuer: string) => JsonWebKey | undefined,
) => Promise<CredentialContent>;

export interface EudiVerifierConfig {
  trustAnchors: TrustAnchor[];
  expectedAudience: string;
  now?: () => number;
  verifier?: CredentialVerifier;
}

export interface VerifiedPresentation {
  issuer: string;
  claims: Record<string, unknown>;
  verifiedAt: number;
}

export interface EudiVerifier {
  verifyPresentation(vpToken: string, expectedNonce: string): Promise<VerifiedPresentation>;
}

export function createEudiVerifier(config: EudiVerifierConfig): EudiVerifier {
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  const anchors = new Map(config.trustAnchors.map((a) => [a.issuer, a.publicKeyJwk]));
  const resolveIssuerKey = (issuer: string) => anchors.get(issuer);
  const verifier: CredentialVerifier = config.verifier ?? defaultCredentialVerifier;

  async function verifyPresentation(
    vpToken: string,
    expectedNonce: string,
  ): Promise<VerifiedPresentation> {
    const content = await verifier(vpToken, resolveIssuerKey);

    if (!content.hasKeyBinding) {
      throw new EudiVerificationError("presentation lacks key binding", "missing_key_binding");
    }
    if (content.keyBindingAudience !== config.expectedAudience) {
      throw new EudiVerificationError("audience mismatch", "audience_mismatch");
    }
    if (content.keyBindingNonce !== expectedNonce) {
      throw new EudiVerificationError("nonce mismatch", "nonce_mismatch");
    }

    const t = now();
    if (content.notBefore !== undefined && t < content.notBefore) {
      throw new EudiVerificationError("credential not yet valid", "not_yet_valid");
    }
    if (content.expiresAt !== undefined && t >= content.expiresAt) {
      throw new EudiVerificationError("credential expired", "expired");
    }

    return { issuer: content.issuer, claims: content.claims, verifiedAt: t };
  }

  return { verifyPresentation };
}
