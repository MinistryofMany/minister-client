import { K as KeyInput, V as VerifiedBadge, E as ExchangeResult, P as PkcePair, M as MinisterClientConfig, a as MinisterClaims, B as BadgesResult } from './types-C8FYcOBP.js';
export { b as MinisterGatingNullifier, c as MinisterTokenError, O as OidcError, d as OidcFlowState, R as RejectedBadge, e as VcVerificationError } from './types-C8FYcOBP.js';
import { JWTPayload } from 'jose';
export { ACCOUNT_AGE_MONTHS, AGE_THRESHOLDS, AccountAgeClaims, AccountAgeMonths, AgeOverClaimsFor, AgeThreshold, BADGE_TYPES, BadgeTypeDef, EmailDomainClaims, EmailExactClaims, FOLLOWERS_BUCKETS, FollowersBucket, InviteCodeClaims, OAUTH_PROVIDERS, OAuthAccountClaims, ResidencyCityClaims, ResidencyCountryClaims, ResidencyStateClaims, SocialFollowingClaims, SybilResistance, TlsnAttestationClaims, badgeScope, badgeScopes, badgeTypeOf, defineBadgeType, getBadgeClaimSchema, knownBadgeTypes, slugForCredentialType } from './badges/index.js';
import 'zod';

interface GetAuthorizationUrlArgs {
    scopes: string[];
    state: string;
    nonce: string;
    codeChallenge: string;
    extraParams?: Record<string, string>;
}
interface ExchangeCodeArgs {
    code: string;
    codeVerifier: string;
    expectedNonce: string;
    idTokenKey?: KeyInput;
    badgeKey?: KeyInput;
}

interface VerifyBadgeOptions {
    issuer: string;
    key?: KeyInput;
}
declare function verifyMinisterBadge(vcJwt: string, options: VerifyBadgeOptions): Promise<VerifiedBadge>;

interface MinisterClient {
    getAuthorizationUrl(args: GetAuthorizationUrlArgs): Promise<string>;
    exchangeCode(args: ExchangeCodeArgs): Promise<ExchangeResult>;
    verifyMinisterBadge(vcJwt: string, options?: {
        key?: KeyInput;
    }): ReturnType<typeof verifyMinisterBadge>;
    generatePkce(): Promise<PkcePair>;
    randomToken(bytes?: number): string;
    badgeScope(slug: string): string;
}
declare function createMinisterClient(config: MinisterClientConfig): MinisterClient;

declare function generatePkce(): Promise<PkcePair>;
declare function randomUrlToken(bytes?: number): string;

declare function buildDid(domain: string): string;
declare function didFromIssuer(issuer: string): string;
declare function buildPairwiseSubjectDid(issuer: string, sub: string): string;
declare function parsePairwiseSubjectDid(subject: string): {
    issuerDid: string;
    sub: string;
} | null;

interface MinisterVerifierConfig {
    issuer: string;
    clientId: string;
    jwks?: KeyInput;
}
interface MinisterVerifier {
    verifyIdToken(idToken: string, opts?: {
        nonce?: string;
    }): Promise<MinisterClaims>;
    verifyBadges(tokenOrPayload: string | JWTPayload): Promise<BadgesResult>;
    verifyBadge(vcJwt: string): Promise<VerifiedBadge>;
}
declare function createMinisterVerifier(config: MinisterVerifierConfig): MinisterVerifier;

interface VerifyIdTokenOptions {
    issuer: string;
    clientId: string;
    nonce?: string;
    key?: KeyInput;
}
declare function verifyMinisterIdToken(idToken: string, options: VerifyIdTokenOptions): Promise<MinisterClaims>;

interface VerifyBadgesOptions {
    issuer: string;
    clientId?: string;
    key?: KeyInput;
}
declare function verifyMinisterBadges(tokenOrPayload: string | JWTPayload, options: VerifyBadgesOptions): Promise<BadgesResult>;

export { BadgesResult, type ExchangeCodeArgs, ExchangeResult, type GetAuthorizationUrlArgs, KeyInput, MinisterClaims, type MinisterClient, MinisterClientConfig, type MinisterVerifier, type MinisterVerifierConfig, PkcePair, VerifiedBadge, type VerifyBadgeOptions, type VerifyBadgesOptions, type VerifyIdTokenOptions, buildDid, buildPairwiseSubjectDid, createMinisterClient, createMinisterVerifier, didFromIssuer, generatePkce, parsePairwiseSubjectDid, randomUrlToken, verifyMinisterBadge, verifyMinisterBadges, verifyMinisterIdToken };
