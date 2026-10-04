import { describe, expect, test } from 'vitest';
import { deobfuscate, obfuscate } from '../../src/v2/obfuscation.js';
import { hexToBuffer } from '../../src/v2/helpers.js';

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

		test('should not expose the AES key when keyPrefixLength is overridden', async () => {
			const obfuscated = await obfuscate(data, { keyPrefixLength: 16 });
			const { cipher, parameters } = JSON.parse(atob(obfuscated));
			expect(parameters.keyPrefix.length).toEqual(32);
			const leakedKey = await crypto.subtle.importKey(
				'raw',
				hexToBuffer(parameters.keyPrefix) as Uint8Array<ArrayBuffer>,
				{ name: 'AES-GCM' },
				false,
				['decrypt']
			);
			await expect(
				crypto.subtle.decrypt(
					{
						name: 'AES-GCM',
						iv: hexToBuffer(cipher.iv) as Uint8Array<ArrayBuffer>,
					},
					leakedKey,
					hexToBuffer(cipher.data) as Uint8Array<ArrayBuffer>
				)
			).rejects.toThrow();
			expect(await deobfuscate(obfuscated)).toEqual(data);
		});
	});
});
