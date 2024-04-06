import type { Challenge, ChallengeOptions, Payload, Solution } from './types.js';
export declare function createChallenge(options: ChallengeOptions): Promise<Challenge>;
export declare function verifySolution(payload: string | Payload, hmacKey: string): Promise<boolean>;
export declare function solveChallenge(challenge: string, salt: string, algorithm?: string, max?: number, start?: number): {
    promise: Promise<Solution | null>;
    controller: AbortController;
};
export declare function solveChallengeWorkers(workerScript: string | URL | (() => Worker), concurrency: number, challenge: string, salt: string, algorithm?: string, max?: number, startNumber?: number): Promise<Solution | null>;
