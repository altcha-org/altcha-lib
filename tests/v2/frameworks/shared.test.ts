import { describe, expect, test, vi } from 'vitest';
import { verify } from '../../../src/v2/frameworks/shared.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';
import { CappedMap } from '../../../src/v2/capped-map.js';
import { bufferToHex, hash, hmac } from '../../../src/v2/helpers.js';
import { HmacAlgorithm } from '../../../src/v2/types.js';

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

		describe('replay protection (client payloads)', () => {
			test('should not let unverified payloads evict used ids from a CappedMap', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 10 });
				const { payload } = await createPayload();
				const first = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(first.error).toBeNull();
				for (let i = 0; i < 10; i++) {
					await verify(
						{ challenge: { parameters: { nonce: `junk${i}` } }, solution: {} },
						deriveKey,
						hmacSignatureSecret,
						undefined,
						store
					);
				}
				const replay = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(replay.error).toBe('ALTCHA payload has been already used.');
			});

			test('should not consume the id of a payload that fails verification', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 10 });
				const { challenge, payload, solution } = await createPayload();
				const wrong = await verify(
					{
						challenge,
						solution: { ...solution, counter: solution!.counter + 1 },
					},
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(wrong.error).toBe('ALTCHA verification failed.');
				const genuine = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(genuine.error).toBeNull();
			});

			test('should accept only one of two concurrent submissions of the same payload', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 10 });
				const { payload } = await createPayload();
				const results = await Promise.all([
					verify(payload, deriveKey, hmacSignatureSecret, undefined, store),
					verify(payload, deriveKey, hmacSignatureSecret, undefined, store),
				]);
				expect(results.map((r) => r.error).sort()).toEqual([
					'ALTCHA payload has been already used.',
					null,
				]);
			});
		});

		describe('replay protection (server-signature payloads)', () => {
			async function signServerPayload(verificationData: string) {
				return {
					algorithm: 'SHA-256',
					id: 'unsigned_id',
					signature: bufferToHex(
						await hmac(
							HmacAlgorithm.SHA_256,
							await hash('SHA-256', verificationData),
							hmacSignatureSecret
						)
					),
					verificationData,
					verified: true,
				};
			}

			test('should reject a replay even when the unsigned top-level id is changed or removed', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 100 });
				const payload = await signServerPayload('id=chl_1&verified=true');
				const { id: _, ...withoutId } = payload;
				const first = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(first.error).toBeNull();
				for (const replay of [
					payload,
					{ ...payload, id: 'other' },
					withoutId,
				]) {
					const result = await verify(
						replay,
						deriveKey,
						hmacSignatureSecret,
						undefined,
						store
					);
					expect(result.error).toBe('ALTCHA payload has been already used.');
				}
			});

			test('should reject a verified payload without a signed id when a store is configured', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 100 });
				const payload = await signServerPayload('verified=true');
				const result = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(result.error).toBe('ALTCHA payload is missing a signed id.');
			});

			test('should not consume the id of a payload that fails verification', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 100 });
				const payload = await signServerPayload('id=chl_1&verified=true');
				const forged = await verify(
					{ ...payload, signature: '00'.repeat(32) },
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(forged.error).toBe('ALTCHA verification failed.');
				const genuine = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					undefined,
					store
				);
				expect(genuine.error).toBeNull();
			});

			test('should key remote (verifyServer) replays on the signed id', async () => {
				const store = new CappedMap<string, boolean>({ maxSize: 100 });
				const fetchMock = vi.fn().mockImplementation(async () =>
					jsonResponse(200, {
						apiKey: 'key_1',
						verificationData: null,
						verified: true,
					})
				);
				const options = {
					fetch: fetchMock,
					url: 'https://sentinel.example.com/v1/verify/signature',
				};
				const payload = {
					algorithm: 'SHA-256',
					id: 'unsigned_id',
					signature: 'sig',
					verificationData: 'id=chl_1&verified=true',
					verified: true,
				};
				const first = await verify(
					payload,
					deriveKey,
					undefined,
					undefined,
					store,
					options
				);
				expect(first.error).toBeNull();
				const replay = await verify(
					{ ...payload, id: 'other' },
					deriveKey,
					undefined,
					undefined,
					store,
					options
				);
				expect(replay.error).toBe('ALTCHA payload has been already used.');
			});
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
