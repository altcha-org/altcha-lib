export type Algorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';
export interface Challenge {
    algorithm: Algorithm;
    challenge: string;
    max?: number;
    salt: string;
    signature: string;
}
export interface ChallengeOptions {
    algorithm?: Algorithm;
    hmacKey: string;
    maxNumber?: number;
    number?: number;
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
export interface Solution {
    number: number;
    took: number;
    worker?: boolean;
}
