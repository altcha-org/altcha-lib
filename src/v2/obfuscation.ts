import { deriveKey as derivedKeyPBKDF2 } from './algorithms/pbkdf2.js';
import {
	deriveChallenge,
	solveChallenge,
	solveChallengeWorkers,
} from './pow.js';
import { bufferToHex, hexToBuffer } from './helpers.js';
import {
	type Challenge,
	type CreateChallengeOptions,
	type DeriveKeyFunction,
	type Solution,
} from './types.js';

type ChallengeWithCipher = Challenge & {
	cipher: {
		iv: string;
		data: string;
	};
};

export async function deobfuscate(
	obfuscatedData: string,
	options: {
		concurrency?: number;
		createWorker?: (algorithm: string) => Worker | Promise<Worker>;
		deriveKey?: DeriveKeyFunction;
	} = {}
) {
	const {
		concurrency = Math.max(
			1,
			Math.min(
				4,
				typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : 1
			)
		),
		createWorker,
		deriveKey = derivedKeyPBKDF2,
	} = options;
	let challenge: ChallengeWithCipher | null = null;
	try {
		challenge = JSON.parse(atob(obfuscatedData));
	} catch {
		throw new Error(`Unable to parse obfuscated data.`);
	}
	if (
		!challenge ||
		typeof challenge !== 'object' ||
		!('parameters' in challenge) ||
		!('cipher' in challenge)
	) {
		throw new Error(`Invalid obfuscated data format.`);
	}
	const cipher = challenge.cipher as {
		iv: string;
		data: string;
	};
	let solution: Solution | null = null;
	if (createWorker) {
		solution = await solveChallengeWorkers({
			challenge,
			concurrency,
			createWorker,
		});
	} else {
		solution = await solveChallenge({
			challenge,
			deriveKey,
		});
	}
	if (!solution) {
		throw new Error('Unable to find solution.');
	}
	const key = await crypto.subtle.importKey(
		'raw',
		hexToBuffer(solution.derivedKey) as Uint8Array<ArrayBuffer>,
		{ name: 'AES-GCM' },
		false,
		['decrypt']
	);
	const result = await crypto.subtle.decrypt(
		{
			name: 'AES-GCM',
			iv: hexToBuffer(cipher.iv) as Uint8Array<ArrayBuffer>,
		},
		key,
		hexToBuffer(cipher.data) as Uint8Array<ArrayBuffer>
	);
	return new TextDecoder().decode(result);
}

export async function obfuscate(
	str: string,
	options: Partial<CreateChallengeOptions> & {
		counterMax?: number;
		counterMin?: number;
		deriveKey?: DeriveKeyFunction;
	} = {}
) {
	const { deriveKey = derivedKeyPBKDF2 } = options;
	const counterMin = options?.counterMin || 20;
	const counterMax = options?.counterMax || 200;
	const { parameters, derivedKey } = await deriveChallenge({
		algorithm: 'PBKDF2/SHA-256',
		cost: 5000,
		deriveKey,
		counter:
			Math.floor(Math.random() * (counterMax - counterMin + 1)) + counterMin,
		...options,
	});
	if (!derivedKey) {
		throw new Error('A counter is required to obfuscate data.');
	}
	// The full derived key is the AES key; `parameters.keyPrefix` exposes only part of it.
	const key = await crypto.subtle.importKey(
		'raw',
		derivedKey as Uint8Array<ArrayBuffer>,
		{ name: 'AES-GCM' },
		false,
		['encrypt']
	);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const data = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: iv },
		key,
		new TextEncoder().encode(str)
	);
	return btoa(
		JSON.stringify({
			parameters,
			cipher: {
				iv: bufferToHex(iv),
				data: bufferToHex(data),
			},
		})
	);
}
