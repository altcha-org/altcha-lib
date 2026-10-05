import { describe, expect, test } from 'vitest';
import {
	PasswordBuffer,
	createChallenge,
	signChallenge,
	solveChallenge,
	verifySolution,
} from '../../src/v2/pow.js';
import {
	bufferToHex,
	canonicalJSON,
	concatBuffers,
	hexToBuffer,
} from '../../src/v2/helpers.js';
import * as pbkdf2 from '../../src/v2/algorithms/pbkdf2.js';
import * as sha from '../../src/v2/algorithms/sha.js';
import {
	Challenge,
	CreateChallengeOptions,
	HmacAlgorithm,
	Solution,
} from '../../src/v2/types.js';

const HMAC_SIGNATURE_SECRET = 'signature.secret';
const HMAC_KEY_SECRET = 'key.secret';

describe('pow', () => {
	describe('bufferToHex()', () => {
		test('should return a HEX string for a buffer', () => {
			expect(bufferToHex(new TextEncoder().encode('Hello World'))).toEqual(
				'48656c6c6f20576f726c64'
			);
		});
	});

	describe('concatBuffers()', () => {
		test('should return concatenated buffers', () => {
			expect(
				concatBuffers(
					new TextEncoder().encode('Hello'),
					new TextEncoder().encode(' World')
				)
			).toStrictEqual(new TextEncoder().encode('Hello World'));
		});
	});

	describe('hexToBuffer()', () => {
		test('should return a buffer for a HEX string', () => {
			expect(hexToBuffer('48656c6c6f20576f726c64')).toStrictEqual(
				new TextEncoder().encode('Hello World')
			);
		});
	});

	describe('canonicalJSON()', () => {
		test('should return JSON string with keys sorted', () => {
			const obj = {
				a: 'a',
				c: 'c',
				b: 'b',
				B: 'B',
				x: {
					a: 'a',
					f: 'f',
					c: 'c',
				},
			};
			const result = canonicalJSON(obj);
			expect(result).toStrictEqual(
				JSON.stringify({
					B: 'B',
					a: 'a',
					b: 'b',
					c: 'c',
					x: {
						a: 'a',
						c: 'c',
						f: 'f',
					},
				})
			);
		});
	});

	describe('signChallenge()', () => {
		test('should return a signed challenge', async () => {
			const challenge: Challenge = {
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: '39baf91a19d671f8231217f9e28342a6',
					salt: '5e00d5d152e1a5db7d44fb6404a40a5e',
					keyPrefix: '00',
					cost: 1000,
					keyLength: 32,
				},
			};
			const result = await signChallenge(
				HmacAlgorithm.SHA_256,
				challenge.parameters,
				null,
				HMAC_SIGNATURE_SECRET,
				HMAC_KEY_SECRET
			);
			expect(result).toEqual({
				parameters: challenge.parameters,
				signature: expect.any(String),
			});
			expect(result.signature).toEqual(
				'a10045ef3381d5516e0c3fd6bf0b90e02fab68d576ffe9e0e1c2d1cd1e404f2a'
			);
		});
	});

	describe('createChallenge()', () => {
		test('should return a new challenge (without signature)', async () => {
			const result = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1000,
				deriveKey: pbkdf2.deriveKey,
			});
			expect(result).toEqual({
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: expect.any(String),
					salt: expect.any(String),
					cost: 1000,
					keyLength: 32,
					keyPrefix: '00',
				},
			});
			expect(result.parameters.nonce.length).toEqual(32);
			expect(result.parameters.salt.length).toEqual(32);
			expect(result.signature).toBeUndefined();
		});

		test('should return a new challenge with fixed counter (without signature)', async () => {
			const result = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1000,
				counter: 1000,
				deriveKey: pbkdf2.deriveKey,
			});
			expect(result).toEqual({
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: expect.any(String),
					salt: expect.any(String),
					cost: 1000,
					keyLength: 32,
					keyPrefix: expect.any(String),
				},
			});
			expect(result.parameters.nonce.length).toEqual(32);
			expect(result.parameters.salt.length).toEqual(32);
			expect(result.parameters.keyPrefix.length).toEqual(32);
			expect(result.signature).toBeUndefined();
		});

		test('should return a new challenge with signature', async () => {
			const result = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1000,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
			});
			expect(result).toEqual({
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: expect.any(String),
					salt: expect.any(String),
					cost: 1000,
					keyLength: 32,
					keyPrefix: '00',
				},
				signature: expect.any(String),
			});
			expect(result.parameters.nonce.length).toEqual(32);
			expect(result.parameters.salt.length).toEqual(32);
			expect(result.signature?.length).toEqual(64);
		});

		test('should return a new challenge in deterministic mode with key signature', async () => {
			const result = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1000,
				counter: 1000,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
			});
			expect(result).toEqual({
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: expect.any(String),
					salt: expect.any(String),
					cost: 1000,
					keyLength: 32,
					keyPrefix: expect.any(String),
					keySignature: expect.any(String),
				},
				signature: expect.any(String),
			});
			expect(result.parameters.nonce.length).toEqual(32);
			expect(result.parameters.salt.length).toEqual(32);
			expect(result.parameters.keyPrefix.length).toEqual(32);
			expect(result.parameters.keySignature?.length).toEqual(64);
			expect(result.signature?.length).toEqual(64);
		});

		test.each([
			{ keyPrefixLength: 32 },
			{ keyPrefixLength: 64 },
			{ keyPrefixLength: 0 },
			{ keyPrefixLength: -1 },
			{ keyPrefixLength: 1.5 },
			{ keyLength: 1 },
		])(
			'should reject a key prefix that is empty or covers the whole key (%o)',
			async (options) => {
				await expect(
					createChallenge({
						algorithm: 'PBKDF2/SHA-256',
						cost: 1,
						counter: 1,
						deriveKey: pbkdf2.deriveKey,
						hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
						hmacKeySignatureSecret: HMAC_KEY_SECRET,
						...options,
					})
				).rejects.toThrow(/keyPrefixLength/);
			}
		);

		test('should reject a default prefix covering a derived key shorter than keyLength', async () => {
			// SHA-256 yields 32 bytes even when keyLength is 64, so the default prefix (32) is the whole key.
			await expect(
				createChallenge({
					algorithm: 'SHA-256',
					cost: 1,
					counter: 1,
					deriveKey: sha.deriveKey,
					keyLength: 64,
				})
			).rejects.toThrow(/derived key length \(32 bytes\)/);
		});

		test('should lowercase keyPrefix before signing', async () => {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				keyPrefix: 'ABC',
			});
			expect(challenge.parameters.keyPrefix).toEqual('abc');
			const solution = (await solveChallenge({
				challenge,
				deriveKey: pbkdf2.deriveKey,
			})) as Solution;
			expect(solution.derivedKey.startsWith('abc')).toBe(true);
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				solution,
			});
			expect(result.verified).toBe(true);
		});

		test('should solve and verify a signed odd-length uppercase keyPrefix from another issuer', async () => {
			const { parameters } = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1,
				deriveKey: pbkdf2.deriveKey,
			});
			// Signed as-is, as an older version or another port would issue it.
			const challenge = await signChallenge(
				HmacAlgorithm.SHA_256,
				{ ...parameters, keyPrefix: 'A' },
				undefined,
				HMAC_SIGNATURE_SECRET
			);
			const solution = (await solveChallenge({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				timeout: 5_000,
			})) as Solution;
			expect(solution).not.toBeNull();
			expect(solution.derivedKey.startsWith('a')).toBe(true);
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				solution,
			});
			expect(result.verified).toBe(true);
		});

		test('should cap keyPrefixLength at half the derived key', async () => {
			const result = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 1,
				counter: 1,
				deriveKey: pbkdf2.deriveKey,
				keyPrefixLength: 24,
			});
			expect(result.parameters.keyPrefix.length).toEqual(32);
		});

		test('should reject an empty keyPrefix', async () => {
			await expect(
				createChallenge({
					algorithm: 'PBKDF2/SHA-256',
					cost: 1,
					deriveKey: pbkdf2.deriveKey,
					hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
					keyPrefix: '',
				})
			).rejects.toThrow('keyPrefix must be a non-empty hex string.');
		});

		test.each(['zz', '-1', 'z', '0x00'])(
			'should reject a non-hex keyPrefix (%s)',
			async (keyPrefix) => {
				await expect(
					createChallenge({
						algorithm: 'PBKDF2/SHA-256',
						cost: 1,
						deriveKey: pbkdf2.deriveKey,
						hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
						keyPrefix,
					})
				).rejects.toThrow('keyPrefix must be a non-empty hex string.');
			}
		);

		test.each([2 ** 32, -1, 1.5])(
			'should reject a counter the challenge cannot encode (%d)',
			async (counter) => {
				await expect(
					createChallenge({
						algorithm: 'PBKDF2/SHA-256',
						cost: 1,
						counter,
						deriveKey: pbkdf2.deriveKey,
					})
				).rejects.toThrow('counter must be an integer from 0 to 4294967295');
			}
		);

		test('should reject a keyPrefix longer than the key', async () => {
			await expect(
				createChallenge({
					algorithm: 'PBKDF2/SHA-256',
					cost: 1,
					deriveKey: pbkdf2.deriveKey,
					keyLength: 2,
					keyPrefix: '00000',
				})
			).rejects.toThrow('must not be longer than the key');
		});

		test('should reject an unsupported hmacAlgorithm', async () => {
			await expect(
				createChallenge({
					algorithm: 'PBKDF2/SHA-256',
					cost: 1,
					deriveKey: pbkdf2.deriveKey,
					hmacAlgorithm: 'SHA-1' as HmacAlgorithm,
					hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				})
			).rejects.toThrow('Unsupported algorithm: SHA-1');
		});

		test.each([
			{ hmacSignatureSecret: '' },
			{ hmacSignatureSecret: null },
			{
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: '',
			},
			{ hmacKeySignatureSecret: HMAC_KEY_SECRET },
		])(
			'should reject empty, null or orphaned secrets (%o)',
			async (secrets) => {
				await expect(
					createChallenge({
						algorithm: 'PBKDF2/SHA-256',
						cost: 1,
						counter: 1,
						deriveKey: pbkdf2.deriveKey,
						...(secrets as Record<string, string>),
					})
				).rejects.toThrow(/hmac(Key)?SignatureSecret/);
			}
		);
	});

	describe('solveChallenge()', () => {
		test('should return a solution', async () => {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 100,
				deriveKey: pbkdf2.deriveKey,
			});
			const solution = await solveChallenge({
				challenge,
				deriveKey: pbkdf2.deriveKey,
			});
			expect(solution).toEqual({
				counter: expect.any(Number),
				derivedKey: expect.any(String),
				time: expect.any(Number),
			});
			expect(solution?.derivedKey?.length).toEqual(64);
		});

		test('should timeout and return null', async () => {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 100,
				counter: 1_000_000,
				deriveKey: pbkdf2.deriveKey,
			});
			const solution = await solveChallenge({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				timeout: 1_000, // 1 second timeout
			});
			expect(solution).toEqual(null);
		});

		test.each([
			['', 'keyPrefix must be a non-empty hex string.'],
			['z', 'keyPrefix must be a non-empty hex string.'],
			['zz', 'keyPrefix must be a non-empty hex string.'],
			['0'.repeat(65), 'must not be longer than the key'],
		])(
			'should throw immediately for an unsolvable keyPrefix (%s)',
			async (keyPrefix, message) => {
				const challenge = await createChallenge({
					algorithm: 'PBKDF2/SHA-256',
					cost: 1,
					deriveKey: pbkdf2.deriveKey,
				});
				const start = performance.now();
				await expect(
					solveChallenge({
						challenge: {
							parameters: { ...challenge.parameters, keyPrefix },
						},
						deriveKey: pbkdf2.deriveKey,
						timeout: 5_000,
					})
				).rejects.toThrow(message);
				expect(performance.now() - start).toBeLessThan(1_000);
			}
		);
	});

	describe('verifySolution()', () => {
		const solve = async (options?: Partial<CreateChallengeOptions>) => {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 100,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				...options,
			});
			const solution = (await solveChallenge({
				challenge,
				deriveKey: pbkdf2.deriveKey,
			})) as Solution;
			return {
				challenge,
				solution,
			};
		};

		test('should successfully verify', async () => {
			const { challenge, solution } = await solve();
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution,
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: false,
				time: expect.any(Number),
				verified: true,
			});
		});

		test('should successfully verify in deterministic mode', async () => {
			const { challenge, solution } = await solve({
				counter: 100,
			});
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution,
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: false,
				time: expect.any(Number),
				verified: true,
			});
		});

		test('should throw for an unsupported hmacAlgorithm', async () => {
			const { challenge, solution } = await solve();
			await expect(
				verifySolution({
					challenge,
					deriveKey: pbkdf2.deriveKey,
					hmacAlgorithm: 'SHA-1' as HmacAlgorithm,
					hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
					solution,
				})
			).rejects.toThrow('Unsupported algorithm: SHA-1');
		});

		test.each([
			{ hmacSignatureSecret: '' },
			{ hmacSignatureSecret: null },
			{ hmacSignatureSecret: undefined },
			{
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: '',
			},
		])('should throw for an empty or missing secret (%o)', async (secrets) => {
			const { challenge, solution } = await solve();
			await expect(
				verifySolution({
					challenge,
					deriveKey: pbkdf2.deriveKey,
					solution,
					...(secrets as { hmacSignatureSecret: string }),
				})
			).rejects.toThrow(/hmac(Key)?SignatureSecret must be a non-empty string/);
		});

		describe.each([
			{ path: '4a (key signature)', hmacKeySignatureSecret: HMAC_KEY_SECRET },
			{ path: '4b (re-derive)', hmacKeySignatureSecret: undefined },
		])('malformed solutions, path $path', ({ hmacKeySignatureSecret }) => {
			test.each([
				['non-hex', () => 'zz'.repeat(32)],
				['odd length', () => 'abc'],
				['empty', () => ''],
				['missing', () => undefined],
				['sign prefix', (key: string) => '-1' + key.slice(2)],
				['uppercase of the correct key', (key: string) => key.toUpperCase()],
			])(
				'should return invalidSolution when derivedKey is %s',
				async (_name, malform) => {
					const { challenge, solution } = await solve({ counter: 42 });
					const result = await verifySolution({
						challenge,
						deriveKey: pbkdf2.deriveKey,
						hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
						hmacKeySignatureSecret,
						solution: {
							...solution,
							derivedKey: malform(solution.derivedKey) as string,
						},
					});
					expect(result).toMatchObject({
						invalidSignature: false,
						invalidSolution: true,
						verified: false,
					});
				}
			);
		});

		describe.each([
			{ path: '4a (key signature)', hmacKeySignatureSecret: HMAC_KEY_SECRET },
			{ path: '4b (re-derive)', hmacKeySignatureSecret: undefined },
		])('coerced counters, path $path', ({ hmacKeySignatureSecret }) => {
			test.each([
				['a numeric string', (c: number) => String(c)],
				['wrapped by 2^32', (c: number) => 2 ** 32 + c],
				['fractional', (c: number) => c + 0.5],
				['negative', () => -1],
				['missing', () => undefined],
			])(
				'should return invalidSolution when the counter is %s',
				async (_name, coerce) => {
					const { challenge, solution } = await solve({ counter: 42 });
					const result = await verifySolution({
						challenge,
						deriveKey: pbkdf2.deriveKey,
						hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
						hmacKeySignatureSecret,
						solution: {
							...solution,
							counter: coerce(solution.counter) as number,
						},
					});
					expect(result).toMatchObject({
						invalidSolution: true,
						verified: false,
					});
				}
			);
		});

		test('should return invalidSolution for a missing solution', async () => {
			const { challenge } = await solve();
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				solution: null as unknown as Solution,
			});
			expect(result).toMatchObject({ invalidSolution: true, verified: false });
		});

		test('should reject a challenge with an injected __proto__ parameter', async () => {
			const { challenge, solution } = await solve();
			const tampered = JSON.parse(
				JSON.stringify(challenge).replace(
					'"parameters":{',
					'"parameters":{"__proto__":{"x":1},'
				)
			);
			expect(Object.hasOwn(tampered.parameters, '__proto__')).toBe(true);
			const result = await verifySolution({
				challenge: tampered,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution,
			});
			expect(result).toMatchObject({ invalidSignature: true, verified: false });
		});

		test('should fail verification with invalid HMAC key', async () => {
			const { challenge, solution } = await solve();
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET + 'invalid',
				hmacKeySignatureSecret: HMAC_KEY_SECRET + 'invalid',
				solution,
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: true,
				invalidSolution: null,
				time: expect.any(Number),
				verified: false,
			});
		});

		test('should fail verification with wrong solution counter', async () => {
			const { challenge, solution } = await solve();
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution: {
					...solution,
					counter: solution.counter + 1,
				},
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: true,
				time: expect.any(Number),
				verified: false,
			});
		});

		test('should fail verification when expired', async () => {
			const { challenge, solution } = await solve({
				expiresAt: Math.floor((Date.now() - 1_000) / 1_000),
			});
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution: {
					...solution,
					counter: solution.counter + 1,
				},
			});
			expect(result).toEqual({
				expired: true,
				invalidSignature: null,
				invalidSolution: null,
				time: expect.any(Number),
				verified: false,
			});
		});

		test('should fail verification with a tampered keyPrefix', async () => {
			const { challenge, solution } = await solve();
			const result = await verifySolution({
				challenge: {
					parameters: {
						...challenge.parameters,
						keyPrefix: 'a',
					},
					signature: challenge.signature,
				},
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution,
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: true,
				invalidSolution: null,
				time: expect.any(Number),
				verified: false,
			});
		});

		test('should fail verification with a spoofed solution', async () => {
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 100,
				counter: 100,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
			});
			const result = await verifySolution({
				challenge,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				hmacKeySignatureSecret: HMAC_KEY_SECRET,
				solution: {
					counter: 100,
					derivedKey: challenge.parameters.keyPrefix,
					time: 10,
				},
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: true,
				time: expect.any(Number),
				verified: false,
			});
		});

		test('should fail verification when fallback solution violates keyPrefix', async () => {
			// No hmacKeySignatureSecret -> verifySolution falls back to path 4b,
			// re-deriving the key from the submitted counter.
			const challenge = await createChallenge({
				algorithm: 'PBKDF2/SHA-256',
				cost: 10,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
			});

			// Learn the honest KDF output for counter 0 with exactly one hash computation.
			const honest = {
				counter: 0,
				derivedKey: bufferToHex(
					(
						await pbkdf2.deriveKey(
							challenge.parameters,
							hexToBuffer(challenge.parameters.salt),
							new PasswordBuffer(
								hexToBuffer(challenge.parameters.nonce),
								'uint32'
							).setCounter(0)
						)
					).derivedKey
				),
			};

			// Pick a keyPrefix the honest key is guaranteed not to satisfy: a
			// byte can't be both 0x00 and 0xff.
			const mismatchedPrefix = honest.derivedKey.startsWith('00') ? 'ff' : '00';
			challenge.parameters.keyPrefix = mismatchedPrefix;
			const signed = await signChallenge(
				HmacAlgorithm.SHA_256,
				challenge.parameters,
				undefined,
				HMAC_SIGNATURE_SECRET
			);

			// Submit the honestly-derived key/counter pair (one KDF execution,
			// no prefix search) against the challenge whose signed keyPrefix
			// it does not satisfy.
			const result = await verifySolution({
				challenge: signed,
				deriveKey: pbkdf2.deriveKey,
				hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
				solution: honest,
			});
			expect(result).toEqual({
				expired: false,
				invalidSignature: false,
				invalidSolution: true,
				time: expect.any(Number),
				verified: false,
			});
		});
	});

	describe('PasswordBuffer', () => {
		test.each([
			['uint32', -1],
			['uint32', 2 ** 32],
			['uint32', 1.5],
			['uint32', NaN],
			['string', Number.MAX_SAFE_INTEGER + 1],
			['string', -1],
		] as const)(
			'should throw for an out-of-range counter (%s, %d)',
			(mode, counter) => {
				const password = new PasswordBuffer(new Uint8Array(16), mode);
				expect(() => password.setCounter(counter)).toThrow(RangeError);
			}
		);

		test('should encode the largest counter of each mode exactly', () => {
			const nonce = new Uint8Array(16);
			expect(
				bufferToHex(new PasswordBuffer(nonce).setCounter(0xffffffff).slice(-4))
			).toEqual('ffffffff');
			expect(
				new TextDecoder().decode(
					new PasswordBuffer(nonce, 'string')
						.setCounter(Number.MAX_SAFE_INTEGER)
						.slice(16)
				)
			).toEqual('9007199254740991');
		});

		test('should return buffer with uint32 (single byte)', () => {
			const counter = 123;
			const nonce = crypto.getRandomValues(new Uint8Array(16));
			const password = new PasswordBuffer(nonce);
			const result = password.setCounter(counter);
			expect(result.slice(-4)).toStrictEqual(
				new Uint8Array([0, 0, 0, counter])
			);
		});

		test('should return buffer with uint32 (multiple bytes)', () => {
			const counter = 9999999;
			const nonce = crypto.getRandomValues(new Uint8Array(16));
			const password = new PasswordBuffer(nonce);
			const result = password.setCounter(counter);

			// verification buffer
			const buf = new Uint8Array(nonce.length + 4);
			buf.set(nonce, 0);
			const dataView = new DataView(buf.buffer);
			dataView.setUint32(nonce.length, counter, false);

			expect(result).toStrictEqual(buf);
			expect(
				new DataView(result.buffer).getUint32(nonce.length, false)
			).toEqual(counter);
		});
	});
});
