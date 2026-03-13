import { describe, expect, test } from 'vitest';
import { deobfuscate, obfuscate } from '../../src/v2/obfuscation.js';

describe('Obfuscation', () => {
	const data = 'mailto:hello@example.com';

	describe('obfuscate()', () => {
		test('should return base64 encode data', async () => {
			const result = await obfuscate(data);
			expect(result).toBeTypeOf('string');
			expect(JSON.parse(atob(result))).toEqual({
				cipher: {
					data: expect.any(String),
					iv: expect.any(String),
				},
				parameters: {
					algorithm: 'PBKDF2/SHA-256',
					nonce: expect.any(String),
					salt: expect.any(String),
					keyPrefix: expect.any(String),
					cost: expect.any(Number),
					keyLength: expect.any(Number),
				},
			});
		});
	});

	describe('deobfuscate()', () => {
		test('should return readable data', async () => {
			const obfuscated = await obfuscate(data);
			const result = await deobfuscate(obfuscated);
			expect(result).toEqual(data);
		});
	});
});
