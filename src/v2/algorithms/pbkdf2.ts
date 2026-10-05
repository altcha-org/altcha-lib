import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import { assertAlgorithm } from '../helpers.js';
import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';

const pbkdf2Async = promisify(pbkdf2);

const DIGESTS = {
	'PBKDF2/SHA-256': 'sha256',
	'PBKDF2/SHA-384': 'sha384',
	'PBKDF2/SHA-512': 'sha512',
} as const;

function getDigest(algorithm: string) {
	assertAlgorithm(algorithm, Object.keys(DIGESTS) as (keyof typeof DIGESTS)[]);
	return DIGESTS[algorithm];
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
