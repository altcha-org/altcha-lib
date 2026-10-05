import { afterEach, describe, expect, test, vi } from 'vitest';
import {
	parseVerificationData,
	verifyFieldsHash,
	verifyServerSignature,
} from '../../src/v2/server-signature.js';
import { bufferToHex, hash, hmac } from '../../src/v2/helpers';
import { HmacAlgorithm } from '../../src/v2/types.js';

describe('Server Signature', () => {
	describe('parseVerificationData()', () => {
		test('should return an object with parsed verification data', () => {
			expect(
				parseVerificationData(
					'expire=12345&time=1.2&score=2.5&fields=a,b,c&verified=true'
				)
			).toEqual({
				expire: 12345,
				time: 1.2,
				score: 2.5,
				fields: ['a', 'b', 'c'],
				verified: true,
			});
		});
	});

	describe('verifyFieldsHash()', () => {
		test('should return true if the fields hash matches', async () => {
			const algorithm = 'SHA-256';
			const formData = new FormData();
			formData.set('a', '1');
			formData.set('b', '2');
			expect(
				await verifyFieldsHash({
					fields: ['a', 'b'],
					fieldsHash: bufferToHex(
						await hash(
							algorithm,
							Object.values(Object.fromEntries(formData)).join('\n')
						)
					),
					formData,
				})
			).toEqual(true);
		});

		test('should return true if the fields hash matches with multi-line values', async () => {
			const algorithm = 'SHA-256';
			const formData = new FormData();
			formData.set('a', '1');
			formData.set('b', 'multi\r\nline\nvalue');
			expect(
				await verifyFieldsHash({
					fields: ['a', 'b'],
					fieldsHash: bufferToHex(
						await hash(
							algorithm,
							Object.values(Object.fromEntries(formData)).join('\n')
						)
					),
					formData,
				})
			).toEqual(true);
		});

		test('should return false if the fields data are tampered', async () => {
			const algorithm = 'SHA-256';
			const formData = new FormData();
			formData.set('a', '1');
			formData.set('b', '2');
			const fieldsHash = bufferToHex(
				await hash(
					algorithm,
					Object.values(Object.fromEntries(formData)).join('\n')
				)
			);
			formData.set('b', '3');
			expect(
				await verifyFieldsHash({
					fields: ['a', 'b'],
					fieldsHash,
					formData,
				})
			).toEqual(false);
		});

		test('should throw for an unsupported algorithm', async () => {
			await expect(
				verifyFieldsHash({
					algorithm: 'MD5',
					fields: ['a'],
					fieldsHash: '',
					formData: { a: '1' },
				})
			).rejects.toThrow('Unsupported algorithm: MD5');
		});
	});

	describe('verifyServerSignature()', () => {
		const algorithm = HmacAlgorithm.SHA_256;
		const hmacSecret = 'secret';

		test('should return successful verification result', async () => {
			const verificationData = 'verified=true';
			const signature = bufferToHex(
				await hmac(
					algorithm,
					await hash(algorithm, verificationData),
					hmacSecret
				)
			);
			expect(
				await verifyServerSignature({
					hmacSecret,
					payload: {
						algorithm,
						signature,
						verificationData,
						verified: true,
					},
				})
			).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: false,
				time: expect.any(Number),
				verificationData: parseVerificationData(verificationData),
				verified: true,
			});
		});

		test('should return failed verification result if unverified', async () => {
			const verificationData = `verified=false`;
			const signature = bufferToHex(
				await hmac(
					algorithm,
					await hash(algorithm, verificationData),
					hmacSecret
				)
			);
			expect(
				await verifyServerSignature({
					hmacSecret,
					payload: {
						algorithm,
						signature,
						verificationData,
						verified: true,
					},
				})
			).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: true,
				time: expect.any(Number),
				verificationData: parseVerificationData(verificationData),
				verified: false,
			});
		});

		test('should return failed verification result if signature is incorrect', async () => {
			const verificationData = `verified=true`;
			const signature = bufferToHex(
				await hmac(
					algorithm,
					await hash(algorithm, verificationData),
					'invalid'
				)
			);
			expect(
				await verifyServerSignature({
					hmacSecret,
					payload: {
						algorithm,
						signature,
						verificationData,
						verified: true,
					},
				})
			).toEqual({
				expired: false,
				invalidSignature: true,
				invalidSolution: false,
				time: expect.any(Number),
				verificationData: parseVerificationData(verificationData),
				verified: false,
			});
		});

		test('should return failed verification result if expired', async () => {
			const verificationData = `expire=${Math.floor(Date.now() - 1_000) / 1_000}&verified=true`;
			const signature = bufferToHex(
				await hmac(
					algorithm,
					await hash(algorithm, verificationData),
					hmacSecret
				)
			);
			expect(
				await verifyServerSignature({
					hmacSecret,
					payload: {
						algorithm,
						signature,
						verificationData,
						verified: true,
					},
				})
			).toEqual({
				expired: true,
				invalidSignature: false,
				invalidSolution: false,
				time: expect.any(Number),
				verificationData: parseVerificationData(verificationData),
				verified: false,
			});
		});

		describe('expiry', () => {
			afterEach(() => {
				vi.useRealTimers();
			});

			async function verifyAt(now: number, verificationData: string) {
				vi.useFakeTimers({ now, toFake: ['Date'] });
				const signature = bufferToHex(
					await hmac(
						algorithm,
						await hash(algorithm, verificationData),
						hmacSecret
					)
				);
				return verifyServerSignature({
					hmacSecret,
					payload: { algorithm, signature, verificationData, verified: true },
				});
			}

			test('should expire as soon as the current second passes expire', async () => {
				const result = await verifyAt(
					1_790_000_000_500,
					'expire=1790000000&verified=true'
				);
				expect(result).toMatchObject({ expired: true, verified: false });
			});

			test('should not expire while within the expire second', async () => {
				const result = await verifyAt(
					1_790_000_000_000,
					'expire=1790000000&verified=true'
				);
				expect(result).toMatchObject({ expired: false, verified: true });
			});

			test.each(['verified=true', 'expire=&verified=true'])(
				'should not expire without an expire value, as Sentinel issues for challenges without expiresAt (%s)',
				async (verificationData) => {
					const result = await verifyAt(1_790_000_000_000, verificationData);
					expect(result).toMatchObject({ expired: false, verified: true });
				}
			);
		});

		test.each([undefined, null, 123])(
			'should return invalidSignature for a non-string signature (%s)',
			async (signature) => {
				const result = await verifyServerSignature({
					hmacSecret,
					payload: {
						algorithm,
						signature: signature as unknown as string,
						verificationData: 'verified=true',
						verified: true,
					},
				});
				expect(result).toMatchObject({
					invalidSignature: true,
					verified: false,
				});
			}
		);

		test.each(['MD5', 'sha-256', 'HS256', undefined])(
			'should throw for an unsupported or missing algorithm (%s)',
			async (badAlgorithm) => {
				const verificationData = 'verified=true';
				const signature = bufferToHex(
					await hmac(
						algorithm,
						await hash(algorithm, verificationData),
						hmacSecret
					)
				);
				await expect(
					verifyServerSignature({
						hmacSecret,
						payload: {
							algorithm: badAlgorithm as string,
							signature,
							verificationData,
							verified: true,
						},
					})
				).rejects.toThrow(`Unsupported algorithm: ${badAlgorithm}`);
			}
		);

		test.each(['', null, undefined])(
			'should throw for an empty or missing hmacSecret (%s)',
			async (badSecret) => {
				await expect(
					verifyServerSignature({
						hmacSecret: badSecret as string,
						payload: {
							algorithm,
							signature: '00',
							verificationData: 'verified=true',
							verified: true,
						},
					})
				).rejects.toThrow('hmacSecret must be a non-empty string.');
			}
		);

		test('should verify a SHA-1 signature (Sentinel signs v1 challenges with their algorithm)', async () => {
			const verificationData = 'verified=true';
			const signature = bufferToHex(
				await hmac(
					'SHA-1' as HmacAlgorithm,
					await hash('SHA-1', verificationData),
					hmacSecret
				)
			);
			const result = await verifyServerSignature({
				hmacSecret,
				payload: {
					algorithm: 'SHA-1',
					signature,
					verificationData,
					verified: true,
				},
			});
			expect(result.verified).toBe(true);
		});
	});
});
