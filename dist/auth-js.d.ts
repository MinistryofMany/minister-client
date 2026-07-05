import { OIDCConfig } from '@auth/core/providers';
import { JWTPayload } from 'jose';
import { K as KeyInput, B as BadgesResult } from './types-C8FYcOBP.js';

interface MinisterProviderOptions {
    clientId: string;
    clientSecret?: string;
    issuer: string;
    scopes?: string[];
}
declare function ministerProvider(options: MinisterProviderOptions): OIDCConfig<Record<string, unknown>>;
interface MinisterBadgesFromProfileOptions {
    issuer: string;
    key?: KeyInput;
}
declare function ministerBadgesFromProfile(profile: JWTPayload | Record<string, unknown>, options: MinisterBadgesFromProfileOptions): Promise<BadgesResult>;

export { type MinisterBadgesFromProfileOptions, type MinisterProviderOptions, ministerBadgesFromProfile, ministerProvider };
