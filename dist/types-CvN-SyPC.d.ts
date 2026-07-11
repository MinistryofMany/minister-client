import { KeyLike, JWK, JWTVerifyGetKey } from 'jose';

declare class VcVerificationError extends Error {
    constructor(message: string);
}
declare class OidcError extends Error {
    constructor(message: string);
}
declare class MinisterTokenError extends Error {
    constructor(message: string);
}

interface MinisterClientConfig {
    issuer: string;
    clientId: string;
    clientSecret?: string;
    redirectUri: string;
}
interface PkcePair {
    verifier: string;
    challenge: string;
}
interface OidcFlowState {
    state: string;
    nonce: string;
    codeVerifier: string;
    expiresAt: number;
}
interface MinisterClaims {
    sub: string;
    name?: string;
    picture?: string;
    sybil_bucket?: number;
    raw: string;
}
/**
 * Minister's per-relying-party Sybil-dedup nullifier (`mnv1:...`), the value
 * Minister stamps in a disclosed badge's `credentialSubject.nullifier` (M5).
 *
 * BRANDED so it can NEVER be interchanged with the OTHER, unrelated nullifier
 * primitive in this ecosystem — `@ministryofmany/nullifier`'s Poseidon/BN254
 * field string (`poseidon2(toField(sub), contextId)`), which is account-anchored
 * and SNARK-provable. These two are permanently distinct (M3):
 *
 *   | | `@ministryofmany/nullifier` | this `MinisterGatingNullifier` |
 *   |---|---|---|
 *   | math | Poseidon / BN254 | RFC 9497 VOPRF + HMAC-SHA256 |
 *   | anchor | the per-RP `sub` (account) | the credential (email, github id) |
 *   | circuit-usable | YES | NO (gating-only, plaintext compare) |
 *   | catches | same-account-across-contexts | same-credential-across-accounts |
 *
 * There is no conversion between them. A future circuit-usable credential
 * nullifier must be a NEW Poseidon construction, never a bridge from this value.
 *
 * HONESTY: this proves ONE CREDENTIAL, not one person. It is per-site
 * (different, unlinkable at other RPs), stable for the same credential (the same
 * value if any account re-proves it here, surviving account delete/re-create),
 * and only as strong as the credential behind it (see each badge type's
 * `sybilResistance`). Gate on it; do not treat it as a unique-human oracle.
 */
type MinisterGatingNullifier = string & {
    readonly __brand: "MinisterGatingNullifier";
};
/**
 * A signature-verified, schema-validated badge.
 *
 * TEMPORAL JWT CLAIMS ARE DISCLOSURE-SHAPED, NOT ISSUANCE-SHAPED (MIN-1).
 * Minister re-mints every disclosed badge at disclosure time: the VC's
 * `iat`/`nbf` are the disclosure instant and `exp` is disclosure time plus a
 * short presentation TTL (clamped so it never exceeds the badge's real
 * expiry). A fine-grained issuance-derived timestamp would be a stable
 * cross-RP correlator, so none survives disclosure — never derive badge age
 * from `iat`/`exp`.
 *
 * The ONE issuance-derived signal is the deliberately COARSE
 * `issuanceMonth` field below ("YYYY-MM", the UTC calendar month of the
 * badge's true issuance, a reserved `credentialSubject` key stamped by
 * Minister at re-mint). Freshness checks derive from IT: map the month to
 * its bucket START so the computed age is always ≥ the true age (a stale
 * badge can never pass — fail-closed), and accept that sub-month precision
 * is intentionally lost (a `maxAgeDays` of N months works; sub-month gates
 * are out of contract). `@ministryofmany/minister-verify` feeds
 * `@ministryofmany/policy`'s `maxAgeDays` exactly this way, and Minister
 * additionally enforces the same coarse check consent-side before
 * disclosing. Month granularity keeps the field shared-by-many (≤ ~13
 * buckets across a badge population with the default 1-year lifetime,
 * ≈ 3.7 bits), so it is a cohort marker, not a re-identifier.
 */
interface VerifiedBadge {
    type: string;
    claims: Record<string, unknown>;
    subject: string;
    issuanceMonth?: string;
    nullifier?: MinisterGatingNullifier;
    raw: string;
}
interface RejectedBadge {
    raw: string;
    error: VcVerificationError;
}
interface BadgesResult {
    badges: VerifiedBadge[];
    rejected: RejectedBadge[];
}
interface ExchangeResult {
    claims: MinisterClaims;
    badges: VerifiedBadge[];
    rejected: RejectedBadge[];
}
type KeyInput = KeyLike | JWK | Uint8Array | JWTVerifyGetKey;

export { type BadgesResult as B, type ExchangeResult as E, type KeyInput as K, type MinisterClientConfig as M, OidcError as O, type PkcePair as P, type RejectedBadge as R, type VerifiedBadge as V, type MinisterClaims as a, type MinisterGatingNullifier as b, MinisterTokenError as c, type OidcFlowState as d, VcVerificationError as e };
