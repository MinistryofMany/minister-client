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
 * TEMPORAL CLAIMS ARE DISCLOSURE-SHAPED, NOT ISSUANCE-SHAPED (MIN-1).
 * Minister re-mints every disclosed badge at disclosure time: the VC's
 * `iat`/`nbf` are the disclosure instant and `exp` is disclosure time plus a
 * short presentation TTL (clamped so it never exceeds the badge's real
 * expiry). An issuance-derived timestamp would be a stable cross-RP
 * correlator, so none survives disclosure. Consequences for relying parties:
 *
 * - Any RP-side freshness check derived from the VC `iat` is VACUOUS. In
 *   particular, `@ministryofmany/policy`'s `maxAgeDays` — fed by
 *   `@ministryofmany/minister-verify`, which derives `issuedAt` from the VC
 *   `iat` — sees every disclosed badge as seconds old and therefore passes
 *   unconditionally. It is NOT an effective defense-in-depth today.
 * - Freshness is still enforced, but on Minister's side: a `minister_policy`
 *   `maxAgeDays` leaf is evaluated at consent against the badge's true
 *   database issuance time, before anything is disclosed. The composed system
 *   remains safe; only the redundant RP-side check is inert.
 * - Giving RPs a verifiable issuance-age signal without re-opening the
 *   timestamp-correlation channel (e.g. a coarse bucketed age claim) is a
 *   tracked design follow-up — do not repurpose `iat`/`exp` for it.
 */
interface VerifiedBadge {
    type: string;
    claims: Record<string, unknown>;
    subject: string;
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
