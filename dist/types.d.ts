export type Algorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';
export type Classification = 'BAD' | 'GOOD' | 'NEUTRAL';
export interface Challenge {
    algorithm: Algorithm;
    challenge: string;
    maxnumber?: number;
    salt: string;
    signature: string;
}
export interface ChallengeOptions {
    algorithm?: Algorithm;
    expires?: Date;
    hmacKey: string;
    maxnumber?: number;
    maxNumber?: number;
    number?: number;
    params?: Record<string, string>;
    salt?: string;
    saltLength?: number;
}
export interface Payload {
    algorithm: Algorithm;
    challenge: string;
    number: number;
    salt: string;
    signature: string;
}
export interface ServerSignaturePayload {
    algorithm: Algorithm;
    apiKey?: string;
    id?: string;
    signature: string;
    verificationData: string;
    verified: boolean;
}
export interface ServerSignatureVerificationData {
    [key: string]: string | unknown;
    classification?: Classification;
    email?: string;
    expire: number;
    fields?: string[];
    fieldsHash?: string;
    id?: string;
    ipAddress?: string;
    reasons?: string[];
    score?: number;
    time: number;
    verified: boolean;
    /** @deprecated With Sentinel, use location.countryCode */
    country?: string;
    /** @deprecated With Sentinel, use text.language */
    detectedLanguage?: string;
}
export interface Solution {
    number: number;
    took: number;
    worker?: boolean;
}
