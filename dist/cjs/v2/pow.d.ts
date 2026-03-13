import { type CreateChallengeOptions, type Challenge, type ChallengeParameters, type SolveChallengeOptions, type Solution, type VerifySolutionOptions, type VerifySolutionResult, HmacAlgorithm } from './types.js';
/**
 * Manages a buffer that combines a nonce with a counter value.
 * Used to generate unique passwords for each iteration of the challenge solver.
 */
export declare class PasswordBuffer {
    readonly nonce: Uint8Array;
    readonly mode: 'uint32' | 'string';
    readonly COUNTER_BYTES = 4;
    readonly buffer: Uint8Array;
    readonly dataView: DataView;
    readonly encoder: TextEncoder;
    constructor(nonce: Uint8Array, mode?: 'uint32' | 'string');
    /**
     * Appends the counter to the nonce buffer.
     * In 'string' mode, encodes the counter as a UTF-8 string.
     * In 'uint32' mode, writes the counter as a big-endian 32-bit integer.
     */
    setCounter(n: number): Uint8Array<ArrayBufferLike>;
}
/**
 * Creates a new proof-of-work challenge.
 *
 * Generates random nonce and salt, optionally pre-computes a key prefix
 * from a known counter value, and optionally signs the challenge with HMAC.
 */
export declare function createChallenge(options: CreateChallengeOptions): Promise<Challenge>;
/**
 * Solves a challenge by brute-forcing counter values until the derived key
 * starts with the required prefix. Returns the solution or null on timeout/abort.
 */
export declare function solveChallenge(options: SolveChallengeOptions): Promise<Solution | null>;
/**
 * Solves a challenge using multiple Web Workers in parallel.
 * Each worker tests a different subset of counter values (interleaved by concurrency).
 * Automatically retries with fewer workers on out-of-memory errors.
 */
export declare function solveChallengeWorkers(options: Omit<SolveChallengeOptions, 'deriveKey'> & {
    concurrency: number;
    createWorker: (algorithm: string) => Worker | Promise<Worker>;
    onOutOfMemory?: (concurrency: number) => number | void;
}): Promise<Solution | null>;
/**
 * Signs challenge parameters with HMAC.
 * Optionally also signs the derived key separately for additional verification.
 */
export declare function signChallenge(algorithm: HmacAlgorithm, parameters: ChallengeParameters, derivedKey: Uint8Array | null | undefined, hmacSignatureSecret: string, hmacKeySignatureSecret?: string): Promise<{
    parameters: ChallengeParameters;
    signature: string;
}>;
/**
 * Verifies a submitted solution against a challenge.
 *
 * Checks (in order):
 * 1. Whether the challenge has expired.
 * 2. Whether the challenge has signature parameter.
 * 3. Whether the challenge signature is valid (tamper check).
 * 4. Whether the derived key matches — either via key signature or by re-deriving.
 */
export declare function verifySolution(options: VerifySolutionOptions): Promise<VerifySolutionResult>;
