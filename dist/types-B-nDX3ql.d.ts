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
    raw: string;
}
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

export { type BadgesResult as B, type ExchangeResult as E, type KeyInput as K, type MinisterClientConfig as M, OidcError as O, type PkcePair as P, type RejectedBadge as R, type VerifiedBadge as V, type MinisterClaims as a, MinisterTokenError as b, type OidcFlowState as c, VcVerificationError as d };
