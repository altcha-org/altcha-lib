export interface Challenge {
	codeChallenge?: CodeChallenge;
	parameters: ChallengeParameters;
	signature?: string;
}

export interface ChallengeParameters {
	algorithm: string;
	nonce: string;
	salt: string;
	cost: number;
	keyLength: number;
	keyPrefix: string;
	keySignature?: string;
	memoryCost?: number;
	parallelism?: number;
	expiresAt?: number;
	data?: Record<string, string | number | boolean | null>;
}

export interface CodeChallenge {
	image: string;
	audio?: string;
	length?: number;
}

export interface CreateChallengeOptions {
	/**
	 * Key derivation algorithm used for the challenge.
	 * Common values: `'PBKDF2/SHA-256'`, `'ARGON2ID'`, `'SCRYPT'`.
	 */
	algorithm: string;
	/**
	 * Randomly selected integer used as the starting counter in deterministic mode.
	 */
	counter?: number;
	/**
	 * Encoding format for the counter value.
	 * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
	 */
	counterMode?: 'uint32' | 'string';
	/**
	 * Algorithm-specific cost parameter controlling computational difficulty
	 * (e.g., iteration count for PBKDF2, time cost for Argon2id).
	 */
	cost: number;
	/**
	 * Arbitrary key-value metadata embedded in the challenge.
	 */
	data?: Record<string, string | number | boolean | null>;
	/**
	 * Algorithm-specific key derivation function used to generate challenge keys.
	 */
	deriveKey: DeriveKeyFunction;
	/**
	 * Timestamp in seconds or Date after which the challenge is no longer valid.
	 */
	expiresAt?: number | Date;
	/**
	 * HMAC digest algorithm used for signing challenges.
	 * Defaults to `'SHA-256'`.
	 */
	hmacAlgorithm?: HmacAlgorithm;
	/**
	 * HMAC secret used to sign derived keys in deterministic mode.
	 */
	hmacKeySignatureSecret?: string;
	/**
	 * HMAC secret used to sign the challenge payload.
	 */
	hmacSignatureSecret?: string;
	/**
	 * Length of the derived key in bytes.
	 * Defaults to `32`.
	 */
	keyLength?: number;
	/**
	 * Required prefix that the derived key must match for the challenge to be solved.
	 */
	keyPrefix?: string;
	/**
	 * Number of bytes from the derived key used as the prefix in deterministic mode.
	 * Defaults to `keyLength / 2`.
	 */
	keyPrefixLength?: number;
	/**
	 * Algorithm-specific memory cost in KiB (applicable to Argon2id and scrypt).
	 */
	memoryCost?: number;
	/**
	 * Algorithm-specific parallelism setting controlling the parallelism
	 * (applicable to Argon2id and scrypt).
	 */
	parallelism?: number;
}

export type DeriveKeyFunction = (
	parameters: ChallengeParameters,
	salt: Uint8Array,
	password: Uint8Array
) => Promise<DeriveKeyFunctionResult>;

export interface DeriveKeyFunctionResult {
	parameters?: Partial<ChallengeParameters>;
	derivedKey: Uint8Array;
}

export enum HmacAlgorithm {
	SHA_256 = 'SHA-256',
	SHA_384 = 'SHA-384',
	SHA_512 = 'SHA-512',
}

export interface Payload {
	challenge: Omit<Challenge, 'codeChallenge'>;
	solution: Solution;
}

export interface PayloadV1 {
	algorithm: string;
	challenge: string;
	number: number;
	salt: string;
	signature?: string;
	took: number;
}

export interface SetCookieOptions {
	domain?: string;
	name?: string;
	maxAge?: number;
	path?: string;
	sameSite?: string;
	secure?: boolean;
}

export type ServerClassification = 'BAD' | 'GOOD' | 'NEUTRAL';

export interface ServerSignaturePayload {
	algorithm: string;
	apiKey?: string;
	id?: string;
	signature: string;
	verificationData: string;
	verified: boolean;
}

export interface ServerSignatureVerificationData {
	[key: string]: string | unknown;
	classification?: ServerClassification;
	email?: string;
	expire?: number;
	fields?: string[];
	fieldsHash?: string;
	id?: string;
	ipAddress?: string;
	reasons?: string[];
	score?: number;
	time?: number;
	verified?: boolean;
}

export interface ServerVerificationResult {
	algorithm?: string;
	apiKey?: string;
	id?: string;
	payload?: string;
	reason?: string;
	score?: number;
	signature?: string;
	verificationData?: string;
	verified?: boolean;
}

export interface SolveChallengeOptions {
	/**
	 * Challenge object to solve, either decoded from a server payload
	 * or as originally returned by `createChallenge`.
	 */
	challenge: Challenge;
	/**
	 * AbortController for cancelling the solve operation before completion.
	 */
	controller?: AbortController;
	/**
	 * Initial counter value to begin iterating from.
	 * Useful for resuming or partitioning work across multiple solvers.
	 */
	counterStart?: number;
	/**
	 * Increment between counter attempts.
	 * Defaults to `1`.
	 */
	counterStep?: number;
	/**
	 * Encoding format for the counter value.
	 * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
	 */
	counterMode?: 'uint32' | 'string';
	/**
	 * Algorithm-specific key derivation function used to compute candidate keys
	 * for each counter value until a match is found.
	 */
	deriveKey: DeriveKeyFunction;
	/**
	 * Maximum time in milliseconds before the solve attempt is aborted.
	 * Defaults to `90_000` (90 seconds).
	 */
	timeout?: number;
}

export interface Strings {
	ariaLinkLabel: string;
	enterCode: string;
	enterCodeAria: string;
	error: string;
	expired: string;
	footer: string;
	getAudioChallenge: string;
	label: string;
	loading: string;
	reload: string;
	verify: string;
	verificationRequired: string;
	verified: string;
	verifying: string;
	waitAlert: string;
}

export enum State {
	CODE = 'code',
	ERROR = 'error',
	VERIFIED = 'verified',
	VERIFYING = 'verifying',
	UNVERIFIED = 'unverified',
	EXPIRED = 'expired',
}

export interface Solution {
	counter: number;
	derivedKey: string;
	time?: number;
}

export interface VerifyOptions {
	concurrency?: number;
	controller?: AbortController;
	minDuration?: number;
}

export interface VerifyResult {
	challenge?: Challenge;
	payload: string;
	solution?: Solution;
}

export interface VerifyServerSignatureResult extends VerifySolutionResult {
	verificationData?: ServerSignatureVerificationData | null;
}

export interface VerifySolutionOptions {
	/**
	 * Challenge object to verify against, either decoded from the client payload
	 * or as originally returned by `createChallenge`.
	 */
	challenge: Challenge;
	/**
	 * Encoding format for the counter value.
	 * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
	 */
	counterMode?: 'uint32' | 'string';
	/**
	 * Algorithm-specific key derivation function used to recompute the expected key
	 * during verification.
	 */
	deriveKey: DeriveKeyFunction;
	/**
	 * HMAC digest algorithm used when verifying challenge signatures.
	 * Defaults to `'SHA-256'`.
	 */
	hmacAlgorithm?: HmacAlgorithm;
	/**
	 * HMAC secret used to verify derived-key signatures in deterministic mode.
	 */
	hmacKeySignatureSecret?: string;
	/**
	 * HMAC secret used to verify the challenge payload signature.
	 */
	hmacSignatureSecret: string;
	/**
	 * Solution object to validate, either decoded from the client payload
	 * or as returned by `solveChallenge`.
	 */
	solution: Solution;
}

export interface VerifySolutionResult {
	expired: boolean;
	invalidSignature: boolean | null;
	invalidSolution: boolean | null;
	time: number;
	verified: boolean;
}
