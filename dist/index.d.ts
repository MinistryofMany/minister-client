import { K as KeyInput, V as VerifiedBadge, E as ExchangeResult, M as MinisterClientConfig, P as PkcePair, a as MinisterClaims, B as BadgesResult, b as BadgeStatusRef, S as StatusCheck } from './types-4FLblnJS.js';
export { c as MinisterGatingNullifier, d as MinisterTokenError, O as OidcError, e as OidcFlowState, R as RejectedBadge, f as StatusListSnapshot, g as VcVerificationError, p as parseCredentialStatus, v as verifyStatusListCredential } from './types-4FLblnJS.js';
import { JWTPayload } from 'jose';
export { ACCOUNT_AGE_MONTHS, AGE_THRESHOLDS, AccountAgeClaims, AccountAgeMonths, AgeOverClaimsFor, AgeThreshold, BADGE_TYPES, BadgeTypeDef, EmailDomainClaims, EmailExactClaims, FOLLOWERS_BUCKETS, FollowersBucket, InviteCodeClaims, OAUTH_PROVIDERS, OAuthAccountClaims, ResidencyCityClaims, ResidencyCountryClaims, ResidencyStateClaims, SocialFollowingClaims, SybilResistance, TlsnAttestationClaims, badgeScope, badgeScopes, badgeTypeOf, getBadgeClaimSchema, knownBadgeTypes, slugForCredentialType } from './badges/index.js';
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
}
declare function createMinisterClient(config: MinisterClientConfig): MinisterClient;

declare function generatePkce(): Promise<PkcePair>;
declare function randomUrlToken(bytes?: number): string;

declare function buildDid(domain: string): string;
declare function didFromIssuer(issuer: string): string;
declare function buildPairwiseSubjectDid(issuer: string, sub: string): string;

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

type StaleFailMode = "open" | "closed";
interface HighWaterStore {
    get(listUri: string): number | undefined | Promise<number | undefined>;
    set(listUri: string, version: number): void | Promise<void>;
}
interface MinisterStatusCheckerConfig {
    issuer: string;
    pollIntervalMs?: number;
    maxStaleMs?: number;
    staleFailMode?: StaleFailMode;
    key?: KeyInput;
    persistHighWater?: HighWaterStore;
    fetchImpl?: typeof fetch;
    nowFn?: () => number;
}
interface MinisterStatusChecker {
    check(ref: BadgeStatusRef): Promise<StatusCheck>;
    isLatched(ref: BadgeStatusRef): boolean;
}
declare function createMinisterStatusChecker(config: MinisterStatusCheckerConfig): MinisterStatusChecker;

export { BadgeStatusRef, BadgesResult, type ExchangeCodeArgs, ExchangeResult, type GetAuthorizationUrlArgs, type HighWaterStore, KeyInput, MinisterClaims, type MinisterClient, MinisterClientConfig, type MinisterStatusChecker, type MinisterStatusCheckerConfig, type MinisterVerifier, type MinisterVerifierConfig, PkcePair, type StaleFailMode, StatusCheck, VerifiedBadge, type VerifyBadgeOptions, type VerifyBadgesOptions, type VerifyIdTokenOptions, buildDid, buildPairwiseSubjectDid, createMinisterClient, createMinisterStatusChecker, createMinisterVerifier, didFromIssuer, generatePkce, randomUrlToken, verifyMinisterBadge, verifyMinisterBadges, verifyMinisterIdToken };
