import { KeyLike, JWTVerifyGetKey } from 'jose';

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
type KeyInput = KeyLike | Uint8Array | JWTVerifyGetKey;

export { type BadgesResult as B, type ExchangeResult as E, type KeyInput as K, type MinisterClientConfig as M, OidcError as O, type PkcePair as P, type RejectedBadge as R, type VerifiedBadge as V, type MinisterClaims as a, MinisterTokenError as b, type OidcFlowState as c, VcVerificationError as d };
