import type {
	CreateChallengeOptions,
	DeriveKeyFunction,
	Payload,
	ServerSignaturePayload,
	SetCookieOptions,
	VerifySolutionResult,
} from '../types.js';

export interface AltchaOptions {
	/**
	 * Returns configuration options passed to `createChallenge`.
	 * Must include `algorithm` and `cost`; all other `CreateChallengeOptions` fields are optional.
	 */
	createChallengeParameters: () => Pick<
		CreateChallengeOptions,
		'algorithm' | 'cost'
	> &
		Partial<CreateChallengeOptions>;
	/**
	 * Algorithm-specific key derivation function used to generate challenge keys.
	 */
	deriveKey: DeriveKeyFunction;
	/**
	 * Name of the form field that carries the ALTCHA payload.
	 * Defaults to `'altcha'` if not specified.
	 */
	fieldName?: string;
	/**
	 * HMAC secret used to sign and verify challenge signatures.
	 */
	hmacSignatureSecret: string;
	/**
	 * HMAC secret used to sign keys in deterministic mode.
	 */
	hmacKeySignatureSecret?: string;
	/**
	 * Cookie configuration for sending the payload via a cookie.
	 * The `name` field is required; all other `SetCookieOptions` fields are optional.
	 */
	setCookie?: RequireField<SetCookieOptions, 'name'>;
	/**
	 * Store implementation for tracking used challenges and preventing replay attacks.
	 */
	store?: Store;
}

export interface AltchaMiddlewareOptions {
	throwOnFailure?: boolean;
}

export interface AltchaResult {
	error: string | null;
	payload: Payload | ServerSignaturePayload | null;
	verification: VerifySolutionResult | null;
}

export type RequireField<T, K extends keyof T> = Omit<T, K> &
	Required<Pick<T, K>>;

export interface Store {
	get: (key: string) => Promise<unknown> | unknown;
	set: (key: string, value: boolean) => Promise<unknown> | unknown;
}
