import type {
	CreateChallengeOptions,
	DeriveKeyFunction,
	Payload,
	ServerSignaturePayload,
	SetCookieOptions,
	VerifyServerOptions,
	VerifyServerResult,
	VerifySolutionResult,
} from '../types.js';

export type AltchaVerifyServerOptions = Omit<VerifyServerOptions, 'payload'>;

export interface AltchaOptions {
	/**
	 * Returns configuration options passed to `createChallenge`.
	 * Must include `algorithm` and `cost`; all other `CreateChallengeOptions` fields are optional.
	 * Required to use `challengeHandler`; optional if challenges are issued by Sentinel and
	 * only `verifyServer` is used.
	 */
	createChallengeParameters?: () => Pick<
		CreateChallengeOptions,
		'algorithm' | 'cost'
	> &
		Partial<CreateChallengeOptions>;
	/**
	 * Algorithm-specific key derivation function used to generate challenge keys.
	 * Required to use `challengeHandler` or to verify self-hosted (client-type) payloads;
	 * optional if challenges are issued by Sentinel and only `verifyServer` is used.
	 */
	deriveKey?: DeriveKeyFunction;
	/**
	 * Name of the form field that carries the ALTCHA payload.
	 * Defaults to `'altcha'` if not specified.
	 */
	fieldName?: string;
	/**
	 * HMAC secret used to sign and verify challenge signatures.
	 * Optional if `verifyServer` is configured and only Sentinel-issued (server-signed)
	 * payloads are verified remotely.
	 */
	hmacSignatureSecret?: string;
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
	/**
	 * When set, Sentinel-issued (server-signed) payloads are verified remotely via
	 * `POST /v1/verify/signature` instead of locally with `hmacSignatureSecret`.
	 */
	verifyServer?: AltchaVerifyServerOptions;
}

export interface AltchaMiddlewareOptions {
	throwOnFailure?: boolean;
}

export interface AltchaResult {
	error: string | null;
	payload: Payload | ServerSignaturePayload | null;
	verification: VerifySolutionResult | VerifyServerResult | null;
}

export type RequireField<T, K extends keyof T> = Omit<T, K> &
	Required<Pick<T, K>>;

export interface Store {
	get: (key: string) => Promise<unknown> | unknown;
	set: (key: string, value: boolean) => Promise<unknown> | unknown;
}
