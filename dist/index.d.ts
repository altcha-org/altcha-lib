import type { Challenge, ChallengeOptions, Payload } from './types.js';
export declare function createChallenge(options: ChallengeOptions): Promise<Challenge>;
export declare function verifySolution(payload: string | Payload, hmacKey: string): Promise<boolean>;
