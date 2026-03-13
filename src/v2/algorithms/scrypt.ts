import { type BinaryLike, scrypt } from 'node:crypto';
import { promisify } from 'node:util';
import type { ChallengeParameters, DeriveKeyFunctionResult } from '../types.js';

const scryptAsync = promisify<
	BinaryLike,
	BinaryLike,
	number,
	object,
	Uint8Array
>(scrypt);

export async function deriveKey(
	parameters: ChallengeParameters,
	salt: Uint8Array,
	password: Uint8Array
): Promise<DeriveKeyFunctionResult> {
	return {
		parameters: {},
		derivedKey: await scryptAsync(password, salt, parameters.keyLength, {
			blockSize: parameters.memoryCost,
			cost: parameters.cost,
			maxmem: 2 * 128 * parameters.cost * parameters.memoryCost!,
			parallelization: parameters.parallelism || 1,
		}),
	};
}
