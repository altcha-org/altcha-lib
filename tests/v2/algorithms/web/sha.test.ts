import { describe, expect, test } from 'vitest';
import { deriveKey } from '../../../../src/v2/algorithms/web/sha';
import { deriveKey as nodeDeriveKey } from '../../../../src/v2/algorithms/sha';
import { bufferToHex, hexToBuffer } from '../../../../src/v2/helpers';
import { PasswordBuffer } from '../../../../src/v2/pow';
import { ChallengeParameters } from '../../../../src/v2/types';

describe('SHA', () => {
	const nonce = '39baf91a19d671f8231217f9e28342a6';
	const salt = '5e00d5d152e1a5db7d44fb6404a40a5e';
	const parameters: ChallengeParameters = {
		algorithm: 'SHA-256',
		cost: 1,
		keyLength: 32,
		nonce,
		salt,
		keyPrefix: '',
	};

	test('should return a SHA-256 derived key (cost: 1, uint32)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'uint32');
		password.setCounter(123);
		const result = await deriveKey(
			parameters,
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'6deccc5eecdb14c99d57129ef8f2f7d3e71812d8bd022c1caaf9e56512ec186c'
		);
	});

	test('should return a SHA-384 derived key (cost: 1, uint32)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'uint32');
		password.setCounter(123);
		const result = await deriveKey(
			{
				...parameters,
				algorithm: 'SHA-384',
				keyLength: 48,
			},
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'ec783f5767a962569850411504cd657ecd2eeef3219fc36036268c2ee8dd56b7f36f6899a37268634054c7e1267087a4'
		);
	});

	test('should return a SHA-512 derived key (cost: 1, uint32)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'uint32');
		password.setCounter(123);
		const result = await deriveKey(
			{
				...parameters,
				algorithm: 'SHA-512',
				keyLength: 64,
			},
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'ed80526e1213f18539b9898556519535bc08bcc7e4d867e88988f3f3050795f0f7f606a2215896bf1b9f0a20aa0864958899c537057ef3193788b7abefd8cd21'
		);
	});

	test('should return a SHA-256 derived key (cost: 1, string)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'string');
		password.setCounter(123);
		const result = await deriveKey(
			parameters,
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'affc403e053d9c08bcad2cb685a87ca3a0995d0b8a7a44d933e32f4ae73ee25a'
		);
	});

	test('should return a SHA-256 derived key (cost: 2, uint32)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'uint32');
		password.setCounter(123);
		const result = await deriveKey(
			{
				...parameters,
				cost: 2,
			},
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'54129dc0097cb40d1c75bd8dc1e5f713839b285d72f9685a3d91ab76ca2746ad'
		);
	});

	test('should return a SHA-256 derived key (cost: 2, string)', async () => {
		const password = new PasswordBuffer(hexToBuffer(nonce), 'string');
		password.setCounter(123);
		const result = await deriveKey(
			{
				...parameters,
				cost: 2,
			},
			hexToBuffer(salt),
			password.buffer
		);
		expect(bufferToHex(result.derivedKey)).toEqual(
			'2383458575577d0d3353f6f47a93c317b92f5acbdcf60ec281e283aee16ebe6e'
		);
	});

	// The first two vectors are the altcha-lib fixtures used by altcha-lib-cpp's tests.
	test.each([
		{
			algorithm: 'SHA-256',
			keyLength: 16,
			nonce: 'c774801f8b77dcd6b4ac5af3ddef4bf7',
			salt: 'ec872e86862dfbfba12711690a373e1d',
			counter: 555,
			expected: '0024229df5acd9a8f2cd4dfe0b074369',
		},
		{
			algorithm: 'SHA-256',
			keyLength: 64,
			nonce: 'ac5fa4c58c5be6dd7fbbcdb01faf140f',
			salt: 'b377aecf2fde853036e46a3a68cfb71a',
			counter: 791,
			expected:
				'0095329f2cd9eb0d8dce7c2a2f91a626275529c3bcbe56e0a6dafe8c83abf941',
		},
		{
			algorithm: 'SHA-384',
			keyLength: 32,
			nonce,
			salt,
			counter: 123,
			expected:
				'd54f228e73d7c198ca80bbeb113e0b44d27150c5aed3eddfcdfc97aa8a93d4ee',
		},
		{
			algorithm: 'SHA-512',
			keyLength: 32,
			nonce,
			salt,
			counter: 123,
			expected:
				'5be4ab4723e3130b92ba4264c06b9f9dccd804882fafbb169511f1959a28360a',
		},
	])(
		'should match the Node implementation when keyLength differs from the digest size ($algorithm, keyLength $keyLength, cost 10)',
		async ({ algorithm, keyLength, nonce, salt, counter, expected }) => {
			const challengeParameters = {
				...parameters,
				algorithm,
				cost: 10,
				keyLength,
				nonce,
				salt,
			};
			const password = new PasswordBuffer(hexToBuffer(nonce), 'uint32');
			password.setCounter(counter);
			for (const derive of [deriveKey, nodeDeriveKey]) {
				const result = await derive(
					challengeParameters,
					hexToBuffer(salt),
					password.buffer
				);
				expect(bufferToHex(result.derivedKey)).toEqual(expected);
			}
		}
	);
});
