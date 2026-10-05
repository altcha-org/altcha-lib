import { assertAlgorithm, assertPositiveInteger, assertSecret, bufferStartsWith, bufferToHex, canonicalJSON, concatBuffers, constantTimeEqual, delay, hexToBuffer, hmac, sortKeys, timeDuration, } from './helpers.js';
import { HmacAlgorithm, } from './types.js';
const HMAC_ALGORITHMS = Object.values(HmacAlgorithm);
/**
 * Largest counter each mode encodes exactly: `setUint32` wraps above 2^32 - 1, and
 * integers above `Number.MAX_SAFE_INTEGER` are not exactly representable.
 */
const MAX_COUNTER = {
    string: Number.MAX_SAFE_INTEGER,
    uint32: 0xffffffff,
};
function isValidCounter(n, mode) {
    return (Number.isInteger(n) &&
        n >= 0 &&
        n <= MAX_COUNTER[mode]);
}
/**
 * Manages a buffer that combines a nonce with a counter value.
 * Used to generate unique passwords for each iteration of the challenge solver.
 */
export class PasswordBuffer {
    nonce;
    mode;
    COUNTER_BYTES = 4;
    buffer;
    dataView;
    encoder = new TextEncoder();
    constructor(nonce, mode = 'uint32') {
        this.nonce = nonce;
        this.mode = mode;
        this.buffer = new Uint8Array(this.nonce.length + this.COUNTER_BYTES);
        this.buffer.set(this.nonce, 0);
        this.dataView = new DataView(this.buffer.buffer);
    }
    /**
     * Appends the counter to the nonce buffer.
     * In 'string' mode, encodes the counter as a UTF-8 string.
     * In 'uint32' mode, writes the counter as a big-endian 32-bit integer.
     * Throws a RangeError unless the counter is an integer the mode encodes exactly.
     */
    setCounter(n) {
        if (!isValidCounter(n, this.mode)) {
            throw new RangeError(`counter must be an integer from 0 to ${MAX_COUNTER[this.mode]}. Got: ${n}`);
        }
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
export async function deriveChallenge(options) {
    const { algorithm, counter, counterMode = 'uint32', cost, deriveKey, data, expiresAt, keyLength = 32, keyPrefix = '00', keyPrefixLength = Math.floor(keyLength / 2), memoryCost, parallelism, } = options;
    // Validate up front: invalid values would otherwise produce NaN parameters,
    // crash inside a KDF, or silently disable expiry.
    assertPositiveInteger('cost', cost);
    assertPositiveInteger('keyLength', keyLength);
    if (memoryCost !== undefined) {
        assertPositiveInteger('memoryCost', memoryCost);
    }
    if (parallelism !== undefined) {
        assertPositiveInteger('parallelism', parallelism);
    }
    if (counterMode !== 'uint32' && counterMode !== 'string') {
        throw new Error(`counterMode must be 'uint32' or 'string'. Got: ${String(counterMode)}`);
    }
    const expiresAtSeconds = expiresAt instanceof Date
        ? Math.floor(expiresAt.getTime() / 1_000)
        : expiresAt;
    if (expiresAtSeconds !== undefined &&
        !(Number.isFinite(expiresAtSeconds) && expiresAtSeconds > 0)) {
        throw new Error('expiresAt must be a valid Date or a positive number of seconds.');
    }
    const parameters = {
        algorithm,
        nonce: bufferToHex(crypto.getRandomValues(new Uint8Array(16))),
        salt: bufferToHex(crypto.getRandomValues(new Uint8Array(16))),
        cost,
        keyLength,
        memoryCost,
        parallelism,
        keyPrefix,
        expiresAt: expiresAtSeconds,
        data,
    };
    if (counter === undefined) {
        // An empty prefix matches every key, so counter 0 would solve the challenge.
        assertKeyPrefix(keyPrefix, keyLength);
        // Normalize before signing: derived keys are lowercase hex, and several ports
        // compare prefixes as strings.
        parameters.keyPrefix = keyPrefix.toLowerCase();
        return { parameters, derivedKey: null };
    }
    // Deterministic mode: derive the key and extract the prefix the solver must match.
    if (!Number.isInteger(keyPrefixLength) || keyPrefixLength < 1) {
        throw new Error(`keyPrefixLength must be a positive integer. Got: ${keyPrefixLength} (keyLength: ${keyLength}).`);
    }
    const deriveKeyResult = await deriveKey(parameters, hexToBuffer(parameters.salt), new PasswordBuffer(hexToBuffer(parameters.nonce), counterMode).setCounter(counter));
    if (deriveKeyResult.parameters) {
        Object.assign(parameters, deriveKeyResult.parameters);
    }
    const { derivedKey } = deriveKeyResult;
    // A prefix covering the whole key would let the key signature be satisfied without any work.
    if (keyPrefixLength >= derivedKey.length) {
        throw new Error(`keyPrefixLength (${keyPrefixLength}) must be less than the derived key length (${derivedKey.length} bytes).`);
    }
    parameters.keyPrefix = bufferToHex(derivedKey.slice(0, Math.min(keyPrefixLength, Math.floor(derivedKey.length / 2))));
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
export async function createChallenge(options) {
    const { hmacAlgorithm = HmacAlgorithm.SHA_256, hmacKeySignatureSecret, hmacSignatureSecret, } = options;
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
    return signChallenge(hmacAlgorithm, parameters, derivedKey, hmacSignatureSecret, hmacKeySignatureSecret);
}
/**
 * Throws unless `keyPrefix` is a non-empty hex string no longer than the key.
 * A non-hex or overlong prefix can never be matched by any derived key.
 */
function assertKeyPrefix(keyPrefix, keyLength) {
    if (typeof keyPrefix !== 'string' || !/^[0-9a-fA-F]+$/.test(keyPrefix)) {
        throw new Error('keyPrefix must be a non-empty hex string.');
    }
    if (keyPrefix.length > keyLength * 2) {
        throw new Error(`keyPrefix (${keyPrefix.length} hex characters) must not be longer than the key (keyLength: ${keyLength} bytes).`);
    }
}
/**
 * Solves a challenge by brute-forcing counter values until the derived key
 * starts with the required prefix. Returns the solution or null on timeout/abort.
 */
export async function solveChallenge(options) {
    const { challenge, controller, counterMode = 'uint32', counterStart = 0, counterStep = 1, deriveKey, timeout = 90_000, } = options;
    const { nonce, keyLength = 32, keyPrefix, salt } = challenge.parameters;
    // Fail fast: an invalid prefix would otherwise run until the timeout.
    assertKeyPrefix(keyPrefix, keyLength);
    const nonceBuf = hexToBuffer(nonce);
    const saltBuf = hexToBuffer(salt);
    // Odd-length prefixes are compared as hex strings, so match case-insensitively
    // like the byte comparison used for even-length prefixes.
    const keyPrefixHex = keyPrefix.toLowerCase();
    const keyPrefixBuf = keyPrefix.length % 2 === 0 ? hexToBuffer(keyPrefix) : null;
    const password = new PasswordBuffer(nonceBuf, counterMode);
    const start = performance.now();
    let counter = counterStart;
    let iterations = 0;
    let derivedKeyHex = '';
    let lastYield = start;
    while (true) {
        // Check for abort signal or timeout every 10 iterations.
        if (controller?.signal.aborted ||
            (timeout && iterations % 10 === 0 && performance.now() - start > timeout)) {
            return null;
        }
        const { derivedKey } = await deriveKey(challenge.parameters, saltBuf, password.setCounter(counter));
        // Yield to the event loop periodically.
        if (iterations % 10 === 0 && performance.now() - lastYield > 200) {
            await delay(0);
            lastYield = performance.now();
        }
        // Check if the derived key matches the required prefix.
        if (keyPrefixBuf
            ? bufferStartsWith(derivedKey, keyPrefixBuf)
            : bufferToHex(derivedKey).startsWith(keyPrefixHex)) {
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
export async function solveChallengeWorkers(options) {
    const { challenge, concurrency = navigator.hardwareConcurrency, controller = new AbortController(), createWorker, onOutOfMemory = (c) => (c > 1 ? Math.floor(c / 2) : 0), counterMode, timeout, } = options;
    const workersConcurrency = Math.min(16, Math.max(1, concurrency));
    const workersInstances = [];
    const terminate = () => {
        for (const worker of workersInstances) {
            worker.terminate();
        }
    };
    for (let i = 0; i < workersConcurrency; i++) {
        workersInstances.push(await createWorker(challenge.parameters.algorithm));
    }
    let solution = null;
    try {
        // Race all workers — first one to find a solution wins.
        solution = await Promise.race(workersInstances.map((worker, i) => {
            controller.signal.addEventListener('abort', () => {
                worker.postMessage({ type: 'abort' });
            });
            return new Promise((resolve, reject) => {
                worker.addEventListener('error', (err) => {
                    reject(err);
                });
                worker.addEventListener('message', (message) => {
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
            });
        }));
    }
    catch (err) {
        // On OOM, retry with fewer workers if the callback allows it.
        const isOOM = err instanceof Error && !!err?.message?.includes('Out of memory');
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
    }
    finally {
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
export async function signChallenge(algorithm, parameters, derivedKey, hmacSignatureSecret, hmacKeySignatureSecret) {
    if (derivedKey && hmacKeySignatureSecret) {
        parameters.keySignature = bufferToHex(await hmac(algorithm, derivedKey, hmacKeySignatureSecret));
    }
    parameters = sortKeys(parameters);
    return {
        parameters,
        signature: bufferToHex(await hmac(algorithm, JSON.stringify(parameters), hmacSignatureSecret)),
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
export async function verifySolution(options) {
    const { challenge, counterMode, deriveKey, hmacAlgorithm = HmacAlgorithm.SHA_256, hmacKeySignatureSecret, hmacSignatureSecret, solution, } = options;
    assertAlgorithm(hmacAlgorithm, HMAC_ALGORITHMS);
    assertSecret('hmacSignatureSecret', hmacSignatureSecret);
    if (hmacKeySignatureSecret !== undefined) {
        assertSecret('hmacKeySignatureSecret', hmacKeySignatureSecret);
    }
    const start = performance.now();
    // 1. Check expiration.
    if (challenge.parameters.expiresAt &&
        challenge.parameters.expiresAt < Date.now() / 1_000) {
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
    const signatureCheck = bufferToHex(await hmac(hmacAlgorithm, canonicalJSON(challenge.parameters), hmacSignatureSecret));
    const signatureVerified = constantTimeEqual(challenge.signature, signatureCheck);
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
    // hex (as produced by every solver) also makes paths 4a and 4b agree on case, and
    // requiring an exact counter rejects coerced or wrapped values in both paths.
    if (typeof solution?.derivedKey !== 'string' ||
        !/^(?:[0-9a-f]{2})+$/.test(solution.derivedKey) ||
        !isValidCounter(solution.counter, counterMode ?? 'uint32')) {
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
        const derivedKeySignatureCheck = bufferToHex(await hmac(hmacAlgorithm, hexToBuffer(solution.derivedKey), hmacKeySignatureSecret));
        const derivedKeySignatureValid = constantTimeEqual(challenge.parameters.keySignature, derivedKeySignatureCheck);
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
    const { derivedKey } = await deriveKey(challenge.parameters, saltBuf, new PasswordBuffer(nonceBuf, counterMode).setCounter(solution.counter));
    const derivedKeyHex = bufferToHex(derivedKey);
    const keyMatches = constantTimeEqual(derivedKeyHex, solution.derivedKey);
    const keyPrefix = challenge.parameters.keyPrefix;
    const keyPrefixBuf = keyPrefix.length % 2 === 0 ? hexToBuffer(keyPrefix) : null;
    const prefixMatches = keyPrefixBuf
        ? bufferStartsWith(derivedKey, keyPrefixBuf)
        : derivedKeyHex.startsWith(keyPrefix.toLowerCase());
    const invalidSolution = !(keyMatches && prefixMatches);
    return {
        expired: false,
        invalidSignature: false,
        invalidSolution,
        time: timeDuration(start),
        verified: !invalidSolution && signatureVerified,
    };
}
