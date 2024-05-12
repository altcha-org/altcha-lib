import type { Challenge, ChallengeOptions, Payload, ServerSignaturePayload, ServerSignatureVerificationData, Solution } from './types.js';
export declare function createChallenge(options: ChallengeOptions): Promise<Challenge>;
export declare function extractParams(payload: string | Payload | Challenge): {
    [k: string]: string;
};
export declare function verifySolution(payload: string | Payload, hmacKey: string, checkExpires?: boolean): Promise<boolean>;
export declare function verifyServerSignature(payload: string | ServerSignaturePayload, hmacKey: string): Promise<{
    verificationData: ServerSignatureVerificationData | null;
    verified: boolean | null;
}>;
export declare function solveChallenge(challenge: string, salt: string, algorithm?: string, max?: number, start?: number): {
    promise: Promise<Solution | null>;
    controller: AbortController;
};
export declare function solveChallengeWorkers(workerScript: string | URL | (() => Worker), concurrency: number, challenge: string, salt: string, algorithm?: string, max?: number, startNumber?: number): Promise<Solution | null>;
declare const _default: {
    createChallenge: typeof createChallenge;
    extractParams: typeof extractParams;
    solveChallenge: typeof solveChallenge;
    solveChallengeWorkers: typeof solveChallengeWorkers;
    verifyServerSignature: typeof verifyServerSignature;
    verifySolution: typeof verifySolution;
};
export default _default;
