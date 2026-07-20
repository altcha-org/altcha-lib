import { describe, expect, test, vi } from 'vitest';
import { verify } from '../../../src/v2/frameworks/shared.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';

function jsonResponse(status: number, data: unknown) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

describe('Shared', () => {
	const hmacSignatureSecret = 'secret.key';

	async function createPayload(
		options?: Partial<Parameters<typeof createChallenge>[0]>
	) {
		const challenge = await createChallenge({
			algorithm: 'PBKDF2/SHA-256',
			cost: 10,
			counter: 10,
			deriveKey,
			hmacSignatureSecret,
			...options,
		});
		const solution = await solveChallenge({
			challenge,
			deriveKey,
		});
		const payload = btoa(
			JSON.stringify({
				challenge,
				solution,
			})
		);
		return {
			challenge,
			payload,
			solution,
		};
	}

	describe('verify()', () => {
		test('should return successful result for valid payload', async () => {
			const { challenge, payload, solution } = await createPayload();
			const result = await verify(payload, deriveKey, hmacSignatureSecret);
			expect(result).toEqual({
				error: null,
				payload: {
					challenge,
					solution,
				},
				verification: {
					expired: false,
					invalidSignature: false,
					invalidSolution: false,
					time: expect.any(Number),
					verified: true,
				},
			});
		});

		test('should return error result for expired payload', async () => {
			const { challenge, payload, solution } = await createPayload({
				expiresAt: new Date(Date.now() - 1_000),
			});
			const result = await verify(payload, deriveKey, hmacSignatureSecret);
			expect(result).toEqual({
				error: 'ALTCHA verification failed.',
				payload: {
					challenge,
					solution,
				},
				verification: {
					expired: true,
					invalidSignature: null,
					invalidSolution: null,
					time: expect.any(Number),
					verified: false,
				},
			});
		});

		test('should return error result for payload with invalid signature', async () => {
			const { challenge, payload, solution } = await createPayload();
			const result = await verify(payload, deriveKey, 'invalid');
			expect(result).toEqual({
				error: 'ALTCHA verification failed.',
				payload: {
					challenge,
					solution,
				},
				verification: {
					expired: false,
					invalidSignature: true,
					invalidSolution: null,
					time: expect.any(Number),
					verified: false,
				},
			});
		});

		test('should return error result when hmacSignatureSecret is missing for a client payload', async () => {
			const { payload } = await createPayload();
			const result = await verify(payload, deriveKey, undefined);
			expect(result.error).toBe(
				'hmacSignatureSecret is required to verify self-hosted ALTCHA challenges.'
			);
			expect(result.verification).toBeNull();
		});

		test('should return error result when deriveKey is missing for a client payload', async () => {
			const { payload } = await createPayload();
			const result = await verify(payload, undefined, hmacSignatureSecret);
			expect(result.error).toBe(
				'deriveKey is required to verify self-hosted ALTCHA challenges.'
			);
			expect(result.verification).toBeNull();
		});

		describe('remote verification (verifyServer)', () => {
			const sentinelPayload = {
				algorithm: 'HS256',
				id: 'chl_1',
				signature: 'sig',
				verificationData: 'verified=1',
				verified: true,
			};

			test('should verify a server-signature payload remotely when verifyServer is configured', async () => {
				const remoteResult = {
					apiKey: 'key_1',
					verificationData: { verified: true },
					verified: true,
				};
				const fetchMock = vi
					.fn()
					.mockResolvedValue(jsonResponse(200, remoteResult));
				const result = await verify(
					sentinelPayload,
					deriveKey,
					undefined,
					undefined,
					undefined,
					{
						fetch: fetchMock,
						url: 'https://sentinel.example.com/v1/verify/signature',
					}
				);
				expect(result).toEqual({
					error: null,
					payload: sentinelPayload,
					verification: remoteResult,
				});
				expect(fetchMock).toHaveBeenCalledTimes(1);
			});

			test('should surface the remote reason in the error when verification fails', async () => {
				const remoteResult = {
					apiKey: null,
					reason: 'PAYLOAD_ALREADY_USED',
					verificationData: null,
					verified: false,
				};
				const fetchMock = vi
					.fn()
					.mockResolvedValue(jsonResponse(200, remoteResult));
				const result = await verify(
					sentinelPayload,
					deriveKey,
					undefined,
					undefined,
					undefined,
					{
						fetch: fetchMock,
						url: 'https://sentinel.example.com/v1/verify/signature',
					}
				);
				expect(result.error).toBe('PAYLOAD_ALREADY_USED');
				expect(result.verification).toEqual(remoteResult);
			});

			test('should prefer remote verification over local hmacSignatureSecret for server payloads', async () => {
				const remoteResult = {
					apiKey: 'key_1',
					verificationData: null,
					verified: true,
				};
				const fetchMock = vi
					.fn()
					.mockResolvedValue(jsonResponse(200, remoteResult));
				const result = await verify(
					sentinelPayload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					undefined,
					{
						fetch: fetchMock,
						url: 'https://sentinel.example.com/v1/verify/signature',
					}
				);
				expect(result.verification).toEqual(remoteResult);
				expect(fetchMock).toHaveBeenCalledTimes(1);
			});
		});
	});
});
