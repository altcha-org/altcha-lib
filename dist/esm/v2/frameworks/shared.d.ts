import { DeriveKeyFunction, Payload, ServerSignaturePayload, VerifySolutionResult } from '../types.js';
import type { Store } from './types.js';
export declare function deriveHmacKeySecret(masterSecret: string): Promise<string>;
export declare function verify(payload: unknown, deriveKey: DeriveKeyFunction, hmacSignatureSecret: string, hmacKeySignatureSecret?: string, store?: Store): Promise<{
    error: string | null;
    payload: Payload | ServerSignaturePayload | null;
    verification: VerifySolutionResult | null;
}>;
