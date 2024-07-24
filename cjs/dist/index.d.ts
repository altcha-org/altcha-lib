import type { Algorithm, Challenge, ChallengeOptions, Payload, ServerSignaturePayload, ServerSignatureVerificationData, Solution } from './types.js';
/**
 * Creates a challenge for the client to solve.
 *
 * @param {ChallengeOptions} options - Options for creating the challenge.
 * @returns {Promise<Challenge>} The created challenge.
 */
export declare function createChallenge(options: ChallengeOptions): Promise<Challenge>;
/**
 * Extracts parameters from the payload.
 *
 * @param {string | Payload | Challenge} payload - The payload from which to extract parameters.
 * @returns {Record<string, string>} The extracted parameters.
 */
export declare function extractParams(payload: string | Payload | Challenge): {
    [k: string]: string;
};
/**
 * Verifies the solution provided by the client.
 *
 * @param {string | Payload} payload - The payload to verify.
 * @param {string} hmacKey - The HMAC key used for verification.
 * @param {boolean} [checkExpires=true] - Whether to check if the challenge has expired.
 * @returns {Promise<boolean>} Whether the solution is valid.
 */
export declare function verifySolution(payload: string | Payload, hmacKey: string, checkExpires?: boolean): Promise<boolean>;
/**
 * Verifies the hash of form fields.
 *
 * @param {FormData | Record<string, unknown>} formData - The form data to verify.
 * @param {string[]} fields - The fields to include in the hash.
 * @param {string} fieldsHash - The expected hash of the fields.
 * @param {string} [algorithm=DEFAULT_ALG] - The hash algorithm to use.
 * @returns {Promise<boolean>} Whether the fields hash is valid.
 */
export declare function verifyFieldsHash(formData: FormData | Record<string, unknown>, fields: string[], fieldsHash: string, algorithm?: Algorithm): Promise<boolean>;
/**
 * Verifies the server's signature.
 *
 * @param {string | ServerSignaturePayload} payload - The payload to verify.
 * @param {string} hmacKey - The HMAC key used for verification.
 * @returns {Promise<{verificationData: ServerSignatureVerificationData | null, verified: boolean}>} The verification result.
 */
export declare function verifyServerSignature(payload: string | ServerSignaturePayload, hmacKey: string): Promise<{
    verificationData: ServerSignatureVerificationData | null;
    verified: boolean;
}>;
/**
 * Solves a challenge by brute force.
 *
 * @param {string} challenge - The challenge to solve.
 * @param {string} salt - The salt used in the challenge.
 * @param {string} [algorithm='SHA-256'] - The hash algorithm used.
 * @param {number} [max=1e6] - The maximum number to try.
 * @param {number} [start=0] - The starting number.
 * @returns {{promise: Promise<Solution | null>, controller: AbortController}} The solution promise and abort controller.
 */
export declare function solveChallenge(challenge: string, salt: string, algorithm?: string, max?: number, start?: number): {
    promise: Promise<Solution | null>;
    controller: AbortController;
};
/**
 * Solves a challenge using web workers for parallel computation.
 *
 * @param {string | URL | (() => Worker)} workerScript - The worker script or function to create a worker.
 * @param {number} concurrency - The number of workers to use.
 * @param {string} challenge - The challenge to solve.
 * @param {string} salt - The salt used in the challenge.
 * @param {string} [algorithm='SHA-256'] - The hash algorithm used.
 * @param {number} [max=1e6] - The maximum number to try.
 * @param {number} [startNumber=0] - The starting number.
 * @returns {Promise<Solution | null>} The solution, or null if not found.
 */
export declare function solveChallengeWorkers(workerScript: string | URL | (() => Worker), concurrency: number, challenge: string, salt: string, algorithm?: string, max?: number, startNumber?: number): Promise<Solution | null>;
declare const _default: {
    createChallenge: typeof createChallenge;
    extractParams: typeof extractParams;
    solveChallenge: typeof solveChallenge;
    solveChallengeWorkers: typeof solveChallengeWorkers;
    verifyFieldsHash: typeof verifyFieldsHash;
    verifyServerSignature: typeof verifyServerSignature;
    verifySolution: typeof verifySolution;
};
export default _default;
