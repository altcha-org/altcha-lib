import crypto from 'node:crypto';
import { promisify } from 'node:util';
import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';

const argon2Async =
	'argon2' in crypto
		? promisify(crypto.argon2)
		: async () => {
				throw new Error('Argon2 not supported in node:crypto.');
			};

export async function deriveKey(
	parameters: ChallengeParameters,
	salt: Uint8Array,
	password: Uint8Array
): Promise<DeriveKeyFunctionResult> {
	return {
		parameters: {},
		derivedKey: await argon2Async('argon2id', {
			memory: parameters.memoryCost!,
			parallelism: parameters.parallelism || 1,
			nonce: salt,
			message: password,
			passes: parameters.cost,
			tagLength: parameters.keyLength,
		}),
	};
}
