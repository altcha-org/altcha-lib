import { createHash } from 'node:crypto';
import { assertAlgorithm, concatBuffers } from '../helpers.js';
import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';

const DIGESTS = {
	'SHA-256': 'sha256',
	'SHA-384': 'sha384',
	'SHA-512': 'sha512',
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
	const { algorithm, keyLength = 32 } = parameters;
	const iterations = Math.max(1, parameters.cost);
	let data: Uint8Array | undefined = undefined;
	let derivedKey: Uint8Array | undefined = undefined;
	for (let i = 0; i < iterations; i++) {
		if (i === 0) {
			data = concatBuffers(salt, password);
		} else {
			data = derivedKey;
		}
		derivedKey = createHash(getDigest(algorithm)).update(data!).digest();
	}
	return {
		parameters: {},
		derivedKey: derivedKey!.subarray(0, keyLength),
	};
}
