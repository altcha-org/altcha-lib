import {
	assertAlgorithm,
	assertSecret,
	bufferStartsWith,
	bufferToHex,
	canonicalJSON,
	concatBuffers,
	constantTimeEqual,
	delay,
	hexToBuffer,
	hmac,
	sortKeys,
	timeDuration,
} from './helpers.js';
import {
	type CreateChallengeOptions,
	type Challenge,
	type ChallengeParameters,
	type SolveChallengeOptions,
	type Solution,
	type VerifySolutionOptions,
	type VerifySolutionResult,
	HmacAlgorithm,
} from './types.js';

const HMAC_ALGORITHMS = Object.values(HmacAlgorithm);

/**
 * Manages a buffer that combines a nonce with a counter value.
 * Used to generate unique passwords for each iteration of the challenge solver.
 */
export class PasswordBuffer {
	readonly COUNTER_BYTES = 4;

	readonly buffer: Uint8Array;

	readonly dataView: DataView;

	readonly encoder = new TextEncoder();

	constructor(
		readonly nonce: Uint8Array,
		readonly mode: 'uint32' | 'string' = 'uint32'
	) {
		this.buffer = new Uint8Array(this.nonce.length + this.COUNTER_BYTES);
		this.buffer.set(this.nonce, 0);
		this.dataView = new DataView(this.buffer.buffer);
	}

	/**
	 * Appends the counter to the nonce buffer.
	 * In 'string' mode, encodes the counter as a UTF-8 string.
	 * In 'uint32' mode, writes the counter as a big-endian 32-bit integer.
	 */
	setCounter(n: number) {
		if (this.mode === 'string') {
			return concatBuffers(this.nonce, this.encoder.encode(n.toString()));
		}
		this.dataView.setUint32(this.nonce.length, n, false);
		return this.buffer;
	}
}

/**
 * Builds unsigned challenge parameters with a random nonce and salt.
 *
 * In deterministic mode (`counter` set), derives the key for that counter,
 * sets `keyPrefix` from it and returns the derived key. Internal: shared by
 * `createChallenge` and `obfuscate`, not exported from the package entry point.
 */
export async function deriveChallenge(
	options: CreateChallengeOptions
): Promise<{
	parameters: ChallengeParameters;
	derivedKey: Uint8Array | null;
}> {
	const {
		algorithm,
		counter,
		counterMode = 'uint32',
		cost,
		deriveKey,
		data,
		expiresAt,
		keyLength = 32,
		keyPrefix = '00',
		keyPrefixLength = Math.floor(keyLength / 2),
		memoryCost,
		parallelism,
	} = options;
	const parameters: ChallengeParameters = {
		algorithm,
		nonce: bufferToHex(crypto.getRandomValues(new Uint8Array(16))),
		salt: bufferToHex(crypto.getRandomValues(new Uint8Array(16))),
		cost,
		keyLength,
		memoryCost,
		parallelism,
		keyPrefix,
		expiresAt:
			expiresAt instanceof Date
				? Math.floor(expiresAt.getTime() / 1_000)
				: expiresAt,
		data,
	};
	if (counter === undefined) {
		// An empty prefix matches every key, so counter 0 would solve the challenge.
		if (!keyPrefix) {
			throw new Error('keyPrefix must not be empty.');
		}
		return { parameters, derivedKey: null };
	}

	// Deterministic mode: derive the key and extract the prefix the solver must match.
	if (!Number.isInteger(keyPrefixLength) || keyPrefixLength < 1) {
		throw new Error(
			`keyPrefixLength must be a positive integer. Got: ${keyPrefixLength} (keyLength: ${keyLength}).`
		);
	}
	const deriveKeyResult = await deriveKey(
		parameters,
		hexToBuffer(parameters.salt),
		new PasswordBuffer(hexToBuffer(parameters.nonce), counterMode).setCounter(
			counter
		)
	);
	if (deriveKeyResult.parameters) {
		Object.assign(parameters, deriveKeyResult.parameters);
	}
	const { derivedKey } = deriveKeyResult;
	// A prefix covering the whole key would let the key signature be satisfied without any work.
	if (keyPrefixLength >= derivedKey.length) {
		throw new Error(
			`keyPrefixLength (${keyPrefixLength}) must be less than the derived key length (${derivedKey.length} bytes).`
		);
	}
	parameters.keyPrefix = bufferToHex(
		derivedKey.slice(
			0,
			Math.min(keyPrefixLength, Math.floor(derivedKey.length / 2))
		)
	);
	return { parameters, derivedKey };
}

/**
 * Creates a new proof-of-work challenge.
 *
 * Generates random nonce and salt, optionally pre-computes a key prefix
 * from a known counter value, and optionally signs the challenge with HMAC.
 * Omitting `hmacSignatureSecret` creates an unsigned challenge; an empty or `null`
 * secret throws, as does `hmacKeySignatureSecret` without `hmacSignatureSecret`.
 */
export async function createChallenge(
	options: CreateChallengeOptions
): Promise<Challenge> {
	const {
		hmacAlgorithm = HmacAlgorithm.SHA_256,
		hmacKeySignatureSecret,
		hmacSignatureSecret,
	} = options;
	assertAlgorithm(hmacAlgorithm, HMAC_ALGORITHMS);
	if (hmacSignatureSecret !== undefined) {
		assertSecret('hmacSignatureSecret', hmacSignatureSecret);
	}
	if (hmacKeySignatureSecret !== undefined) {
		assertSecret('hmacKeySignatureSecret', hmacKeySignatureSecret);
		if (hmacSignatureSecret === undefined) {
			throw new Error('hmacKeySignatureSecret requires hmacSignatureSecret.');
		}
	}
	const { parameters, derivedKey } = await deriveChallenge(options);

	// Return unsigned challenge if no HMAC secret is provided.
	if (hmacSignatureSecret === undefined) {
		return {
			parameters: sortKeys(parameters),
		};
	}
	return signChallenge(
		hmacAlgorithm,
		parameters,
		derivedKey,
		hmacSignatureSecret,
		hmacKeySignatureSecret
	);
}

/**
 * Solves a challenge by brute-forcing counter values until the derived key
 * starts with the required prefix. Returns the solution or null on timeout/abort.
 */
export async function solveChallenge(
	options: SolveChallengeOptions
): Promise<Solution | null> {
	const {
		challenge,
		controller,
		counterMode = 'uint32',
		counterStart = 0,
		counterStep = 1,
		deriveKey,
		timeout = 90_000,
	} = options;
	const { nonce, keyPrefix, salt } = challenge.parameters;
	const nonceBuf = hexToBuffer(nonce);
	const saltBuf = hexToBuffer(salt);
	const keyPrefixBuf =
		keyPrefix.length % 2 === 0 ? hexToBuffer(keyPrefix) : null;
	const password = new PasswordBuffer(nonceBuf, counterMode);
	const start = performance.now();
	let counter = counterStart;
	let iterations = 0;
	let derivedKeyHex = '';
	let lastYield = start;
	while (true) {
		// Check for abort signal or timeout every 10 iterations.
		if (
			controller?.signal.aborted ||
			(timeout && iterations % 10 === 0 && performance.now() - start > timeout)
		) {
			return null;
		}
		const { derivedKey } = await deriveKey(
			challenge.parameters,
			saltBuf,
			password.setCounter(counter)
		);
		// Yield to the event loop periodically.
		if (iterations % 10 === 0 && performance.now() - lastYield > 200) {
			await delay(0);
			lastYield = performance.now();
		}
		// Check if the derived key matches the required prefix.
		if (
			keyPrefixBuf
				? bufferStartsWith(derivedKey, keyPrefixBuf)
				: bufferToHex(derivedKey).startsWith(keyPrefix)
		) {
			derivedKeyHex = bufferToHex(derivedKey);
			break;
		}
		counter = counter + counterStep;
		iterations = iterations + 1;
	}
	return {
		counter,
		derivedKey: derivedKeyHex,
		time: timeDuration(start),
	};
}

/**
 * Solves a challenge using multiple Web Workers in parallel.
 * Each worker tests a different subset of counter values (interleaved by concurrency).
 * Automatically retries with fewer workers on out-of-memory errors.
 */

export async function solveChallengeWorkers(
	options: Omit<SolveChallengeOptions, 'deriveKey'> & {
		concurrency: number;
		createWorker: (algorithm: string) => Worker | Promise<Worker>;
		onOutOfMemory?: (concurrency: number) => number | void;
	}
) {
	const {
		challenge,
		concurrency = navigator.hardwareConcurrency,
		controller = new AbortController(),
		createWorker,
		onOutOfMemory = (c) => (c > 1 ? Math.floor(c / 2) : 0),
		counterMode,
		timeout,
	} = options;
	const workersConcurrency = Math.min(16, Math.max(1, concurrency));
	const workersInstances: Worker[] = [];
	const terminate = () => {
		for (const worker of workersInstances) {
			worker.terminate();
		}
	};
	for (let i = 0; i < workersConcurrency; i++) {
		workersInstances.push(await createWorker(challenge.parameters.algorithm));
	}
	let solution: Solution | null = null;
	try {
		// Race all workers — first one to find a solution wins.
		solution = await Promise.race(
			workersInstances.map((worker, i) => {
				controller.signal.addEventListener('abort', () => {
					worker.postMessage({ type: 'abort' });
				});
				return new Promise((resolve, reject) => {
					worker.addEventListener('error', (err) => {
						reject(err);
					});
					worker.addEventListener('message', (message: MessageEvent) => {
						if (message.data) {
							// Tell other workers to stop once one finds the answer.
							for (const w of workersInstances) {
								if (w !== worker) {
									w.postMessage({ type: 'abort' });
								}
							}
							if (message.data.error) {
								return reject(new Error(message.data.error));
							}
						}
						resolve(message.data);
					});
					// Each worker starts at a different offset and steps by concurrency count.
					worker.postMessage({
						challenge,
						counterMode,
						counterStart: i,
						counterStep: workersConcurrency,
						timeout,
						type: 'work',
					});
				}) as Promise<Solution | null>;
			})
		);
	} catch (err: unknown) {
		// On OOM, retry with fewer workers if the callback allows it.
		const isOOM =
			err instanceof Error && !!err?.message?.includes('Out of memory');
		if (isOOM) {
			if (onOutOfMemory) {
				terminate();
				const retryConcurrency = onOutOfMemory(workersConcurrency);
				if (retryConcurrency) {
					return solveChallengeWorkers({
						...options,
						challenge,
						controller,
						concurrency: retryConcurrency,
						createWorker,
					});
				}
			}
		}
		throw err;
	} finally {
		terminate();
	}
	if (controller.signal.aborted) {
		return null;
	}
	return solution || null;
}

/**
 * Signs challenge parameters with HMAC.
 * Optionally also signs the derived key separately for additional verification.
 */
export async function signChallenge(
	algorithm: HmacAlgorithm,
	parameters: ChallengeParameters,
	derivedKey: Uint8Array | null | undefined,
	hmacSignatureSecret: string,
	hmacKeySignatureSecret?: string
) {
	if (derivedKey && hmacKeySignatureSecret) {
		parameters.keySignature = bufferToHex(
			await hmac(algorithm, derivedKey, hmacKeySignatureSecret)
		);
	}
	parameters = sortKeys(parameters);
	return {
		parameters,
		signature: bufferToHex(
			await hmac(algorithm, JSON.stringify(parameters), hmacSignatureSecret)
		),
	};
}

/**
 * Verifies a submitted solution against a challenge.
 *
 * Checks (in order):
 * 1. Whether the challenge has expired.
 * 2. Whether the challenge has signature parameter.
 * 3. Whether the challenge signature is valid (tamper check).
 * 4. Whether the derived key matches — either via key signature or by re-deriving.
 */
export async function verifySolution(
	options: VerifySolutionOptions
): Promise<VerifySolutionResult> {
	const {
		challenge,
		counterMode,
		deriveKey,
		hmacAlgorithm = HmacAlgorithm.SHA_256,
		hmacKeySignatureSecret,
		hmacSignatureSecret,
		solution,
	} = options;
	assertAlgorithm(hmacAlgorithm, HMAC_ALGORITHMS);
	assertSecret('hmacSignatureSecret', hmacSignatureSecret);
	if (hmacKeySignatureSecret !== undefined) {
		assertSecret('hmacKeySignatureSecret', hmacKeySignatureSecret);
	}
	const start = performance.now();

	// 1. Check expiration.
	if (
		challenge.parameters.expiresAt &&
		challenge.parameters.expiresAt < Date.now() / 1_000
	) {
		return {
			expired: true,
			invalidSignature: null,
			invalidSolution: null,
			time: timeDuration(start),
			verified: false,
		};
	}

	// 2. Signature parameter check.
	if (!challenge.signature) {
		return {
			expired: false,
			invalidSignature: true,
			invalidSolution: null,
			time: timeDuration(start),
			verified: false,
		};
	}

	// 3. Verify challenge signature to ensure parameters haven't been tampered with.
	const signatureCheck = bufferToHex(
		await hmac(
			hmacAlgorithm,
			canonicalJSON(challenge.parameters),
			hmacSignatureSecret
		)
	);
	const signatureVerified = constantTimeEqual(
		challenge.signature,
		signatureCheck
	);
	if (!signatureVerified) {
		return {
			expired: false,
			invalidSignature: true,
			invalidSolution: null,
			time: timeDuration(start),
			verified: false,
		};
	}

	// A malformed solution is an invalid solution, not an error. Requiring lowercase
	// hex (as produced by every solver) also makes paths 4a and 4b agree on case.
	if (
		typeof solution?.derivedKey !== 'string' ||
		!/^(?:[0-9a-f]{2})+$/.test(solution.derivedKey)
	) {
		return {
			expired: false,
			invalidSignature: false,
			invalidSolution: true,
			time: timeDuration(start),
			verified: false,
		};
	}

	// 4a. If a key signature exists, verify the derived key against it (faster path).
	if (challenge.parameters.keySignature && hmacKeySignatureSecret) {
		const derivedKeySignatureCheck = bufferToHex(
			await hmac(
				hmacAlgorithm,
				hexToBuffer(solution.derivedKey),
				hmacKeySignatureSecret
			)
		);
		const derivedKeySignatureValid = constantTimeEqual(
			challenge.parameters.keySignature,
			derivedKeySignatureCheck
		);
		return {
			expired: false,
			invalidSignature: false,
			invalidSolution: !derivedKeySignatureValid,
			time: timeDuration(start),
			verified: derivedKeySignatureValid,
		};
	}

	// 4b. Otherwise, re-derive the key from the solution's counter, compare it
	// against the submitted key, and require it to satisfy the signed key prefix.
	const nonceBuf = hexToBuffer(challenge.parameters.nonce);
	const saltBuf = hexToBuffer(challenge.parameters.salt);
	const { derivedKey } = await deriveKey(
		challenge.parameters,
		saltBuf,
		new PasswordBuffer(nonceBuf, counterMode).setCounter(solution.counter)
	);
	const derivedKeyHex = bufferToHex(derivedKey);
	const keyMatches = constantTimeEqual(derivedKeyHex, solution.derivedKey);
	const keyPrefix = challenge.parameters.keyPrefix;
	const keyPrefixBuf =
		keyPrefix.length % 2 === 0 ? hexToBuffer(keyPrefix) : null;
	const prefixMatches = keyPrefixBuf
		? bufferStartsWith(derivedKey, keyPrefixBuf)
		: derivedKeyHex.startsWith(keyPrefix);
	const invalidSolution = !(keyMatches && prefixMatches);
	return {
		expired: false,
		invalidSignature: false,
		invalidSolution,
		time: timeDuration(start),
		verified: !invalidSolution && signatureVerified,
	};
}
