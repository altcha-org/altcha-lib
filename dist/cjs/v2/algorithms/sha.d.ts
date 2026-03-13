import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';
export declare function deriveKey(parameters: ChallengeParameters, salt: Uint8Array, password: Uint8Array): Promise<DeriveKeyFunctionResult>;
