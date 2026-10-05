import { assertAlgorithm } from '../../helpers.js';
import type {
	ChallengeParameters,
	DeriveKeyFunctionResult,
} from '../../types.js';

export async function deriveKey(
	parameters: ChallengeParameters,
	salt: Uint8Array,
	password: Uint8Array
): Promise<DeriveKeyFunctionResult> {
	const { algorithm, cost, keyLength = 32 } = parameters;
	assertAlgorithm(algorithm, [
		'PBKDF2/SHA-256',
		'PBKDF2/SHA-384',
		'PBKDF2/SHA-512',
	]);
	const passwordKey = await crypto.subtle.importKey(
		'raw',
		password as Uint8Array<ArrayBuffer>,
		{ name: 'PBKDF2' },
		false,
		['deriveBits']
	);
	// deriveBits supports any key length, unlike deriving an AES key (16, 24 or 32 bytes only).
	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: 'PBKDF2',
			salt: salt as Uint8Array<ArrayBuffer>,
			iterations: cost,
			hash: algorithm.slice('PBKDF2/'.length),
		},
		passwordKey,
		keyLength * 8
	);
	return {
		parameters: {},
		derivedKey: new Uint8Array(derivedBits),
	};
}
