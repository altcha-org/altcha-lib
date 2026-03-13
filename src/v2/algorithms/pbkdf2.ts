import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';

const pbkdf2Async = promisify(pbkdf2);

function getDigest(algorithm: string) {
	switch (algorithm) {
		case 'PBKDF2/SHA-512':
			return 'sha512';
		case 'PBKDF2/SHA-384':
			return 'sha384';
		case 'PBKDF2/SHA-256':
		default:
			return 'sha256';
	}
}

export async function deriveKey(
	parameters: ChallengeParameters,
	salt: Uint8Array,
	password: Uint8Array
): Promise<DeriveKeyFunctionResult> {
	return {
		parameters: {},
		derivedKey: await pbkdf2Async(
			password,
			salt,
			parameters.cost,
			parameters.keyLength,
			getDigest(parameters.algorithm)
		),
	};
}
