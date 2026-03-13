import { describe, expect, test } from 'vitest';
import { verify } from '../../../src/v2/frameworks/shared.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';

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
	});
});
