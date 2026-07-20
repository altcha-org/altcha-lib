import { verifySolution } from '../pow.js';
import { verifyServerSignature } from '../server-signature.js';
import { verifyServer } from '../verify-server.js';
import { bufferToHex, hmac } from '../helpers.js';
import {
	DeriveKeyFunction,
	HmacAlgorithm,
	Payload,
	ServerSignaturePayload,
	VerifyServerResult,
	VerifySolutionResult,
} from '../types.js';
import type { AltchaVerifyServerOptions, Store } from './types.js';

export async function deriveHmacKeySecret(masterSecret: string) {
	return bufferToHex(
		await hmac(HmacAlgorithm.SHA_256, masterSecret, 'derived-secret')
	);
}

export async function verify(
	payload: unknown,
	deriveKey: DeriveKeyFunction | undefined,
	hmacSignatureSecret: string | undefined,
	hmacKeySignatureSecret?: string,
	store?: Store,
	verifyServerOptions?: AltchaVerifyServerOptions
): Promise<{
	error: string | null;
	payload: Payload | ServerSignaturePayload | null;
	verification: VerifySolutionResult | VerifyServerResult | null;
}> {
	if (!payload) {
		return {
			error: 'ALTCHA payload is missing.',
			payload: null,
			verification: null,
		};
	}
	if (typeof payload === 'string') {
		payload = parsePayload(payload);
	}
	if (!payload) {
		return {
			error: 'ALTCHA payload is invalid.',
			payload: null,
			verification: null,
		};
	}
	const type = getPayloadType(payload);
	let verification:
		| Awaited<ReturnType<typeof verifyServerSignaturePayload>>
		| VerifySolutionResult
		| VerifyServerResult
		| null = null;
	let challengeId: string | null | undefined = null;
	try {
		switch (type) {
			case 'client':
				if (!deriveKey) {
					throw new Error(
						'deriveKey is required to verify self-hosted ALTCHA challenges.'
					);
				}
				if (!hmacSignatureSecret) {
					throw new Error(
						'hmacSignatureSecret is required to verify self-hosted ALTCHA challenges.'
					);
				}
				challengeId = getChallengeId(payload as Payload);
				if (store && challengeId) {
					await checkChallengeId(store, challengeId);
				}
				verification = await verifyClientPayload(
					payload as Payload,
					deriveKey,
					hmacSignatureSecret,
					hmacKeySignatureSecret
				);
				break;
			case 'server':
				challengeId = (payload as ServerSignaturePayload).id;
				if (store && challengeId) {
					await checkChallengeId(store, challengeId);
				}
				if (verifyServerOptions) {
					verification = await verifyServer({
						...verifyServerOptions,
						payload: payload as ServerSignaturePayload,
					});
				} else {
					if (!hmacSignatureSecret) {
						throw new Error(
							'hmacSignatureSecret or verifyServer must be configured to verify this payload.'
						);
					}
					verification = await verifyServerSignaturePayload(
						payload as ServerSignaturePayload,
						hmacSignatureSecret
					);
				}
				break;
			default:
				throw new Error('ALTCHA payload is invalid.');
		}
	} catch (err: unknown) {
		return {
			error: err instanceof Error ? err.message : 'Unknown error',
			payload: payload as Payload,
			verification: null,
		};
	}
	if (!verification?.verified) {
		return {
			error:
				(verification && 'reason' in verification && verification.reason) ||
				'ALTCHA verification failed.',
			payload: payload as Payload,
			verification,
		};
	}
	return {
		error: null,
		payload: payload as Payload,
		verification,
	};
}

async function checkChallengeId(store: Store, challengeId: string) {
	if (await store.get(challengeId)) {
		throw new Error('ALTCHA payload has been already used.');
	}
	await store.set(challengeId, true);
}

function getChallengeId(payload: Payload) {
	const { challenge } = payload;
	const data = challenge.parameters.data;
	return data?.challengeId
		? String(data.challengeId)
		: challenge.parameters.nonce;
}

function getPayloadType(payload: unknown) {
	if (!payload || typeof payload !== 'object') {
		return null;
	}
	if ('verificationData' in payload) {
		return 'server';
	}
	if ('challenge' in payload && 'solution' in payload) {
		return 'client';
	}
	return null;
}

function parsePayload(payload: string) {
	try {
		return JSON.parse(atob(payload));
	} catch {
		return null;
	}
}

function verifyClientPayload(
	payload: Payload,
	deriveKey: DeriveKeyFunction,
	hmacSignatureSecret: string,
	hmacKeySignatureSecret?: string
) {
	const { challenge, solution } = payload;
	return verifySolution({
		challenge,
		deriveKey,
		hmacSignatureSecret,
		hmacKeySignatureSecret,
		solution,
	});
}

async function verifyServerSignaturePayload(
	payload: ServerSignaturePayload,
	hmacSecret: string
) {
	return verifyServerSignature({
		payload,
		hmacSecret,
	});
}
