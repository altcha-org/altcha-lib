import { DeriveKeyFunction, Payload, ServerSignaturePayload, VerifyServerResult, VerifySolutionResult } from '../types.js';
import type { AltchaVerifyServerOptions, Store } from './types.js';
export declare function deriveHmacKeySecret(masterSecret: string): Promise<string>;
export declare function verify(payload: unknown, deriveKey: DeriveKeyFunction | undefined, hmacSignatureSecret: string | undefined, hmacKeySignatureSecret?: string, store?: Store, verifyServerOptions?: AltchaVerifyServerOptions): Promise<{
    error: string | null;
    payload: Payload | ServerSignaturePayload | null;
    verification: VerifySolutionResult | VerifyServerResult | null;
}>;
