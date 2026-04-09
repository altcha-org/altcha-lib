"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasswordBuffer = void 0;
exports.createChallenge = createChallenge;
exports.solveChallenge = solveChallenge;
exports.solveChallengeWorkers = solveChallengeWorkers;
exports.signChallenge = signChallenge;
exports.verifySolution = verifySolution;
const helpers_js_1 = require("./helpers.js");
const types_js_1 = require("./types.js");
/**
 * Manages a buffer that combines a nonce with a counter value.
 * Used to generate unique passwords for each iteration of the challenge solver.
 */
class PasswordBuffer {
    constructor(nonce, mode = 'uint32') {
        this.nonce = nonce;
        this.mode = mode;
        this.COUNTER_BYTES = 4;
        this.encoder = new TextEncoder();
        this.buffer = new Uint8Array(this.nonce.length + this.COUNTER_BYTES);
        this.buffer.set(this.nonce, 0);
        this.dataView = new DataView(this.buffer.buffer);
    }
    /**
     * Appends the counter to the nonce buffer.
     * In 'string' mode, encodes the counter as a UTF-8 string.
     * In 'uint32' mode, writes the counter as a big-endian 32-bit integer.
     */
    setCounter(n) {
        if (this.mode === 'string') {
            return (0, helpers_js_1.concatBuffers)(this.nonce, this.encoder.encode(n.toString()));
        }
        this.dataView.setUint32(this.nonce.length, n, false);
        return this.buffer;
    }
}
exports.PasswordBuffer = PasswordBuffer;
/**
 * Creates a new proof-of-work challenge.
 *
 * Generates random nonce and salt, optionally pre-computes a key prefix
 * from a known counter value, and optionally signs the challenge with HMAC.
 */
async function createChallenge(options) {
    const { algorithm, counter, counterMode = 'uint32', cost, deriveKey, data, expiresAt, hmacAlgorithm = types_js_1.HmacAlgorithm.SHA_256, hmacKeySignatureSecret, hmacSignatureSecret, keyLength = 32, keyPrefix = '00', keyPrefixLength = keyLength / 2, memoryCost, parallelism, } = options;
    const parameters = {
        algorithm,
        nonce: (0, helpers_js_1.bufferToHex)(crypto.getRandomValues(new Uint8Array(16))),
        salt: (0, helpers_js_1.bufferToHex)(crypto.getRandomValues(new Uint8Array(16))),
        cost,
        keyLength,
        memoryCost,
        parallelism,
        keyPrefix,
        expiresAt: expiresAt instanceof Date
            ? Math.floor(expiresAt.getTime() / 1_000)
            : expiresAt,
        data,
    };
    // If a counter is provided, derive the key and extract the prefix the solver must match.
    let deriveKeyResult = null;
    if (counter !== undefined) {
        const nonceBuf = (0, helpers_js_1.hexToBuffer)(parameters.nonce);
        deriveKeyResult = await deriveKey(parameters, (0, helpers_js_1.hexToBuffer)(parameters.salt), new PasswordBuffer(nonceBuf, counterMode).setCounter(counter));
        if (deriveKeyResult.parameters) {
            Object.assign(parameters, deriveKeyResult.parameters);
        }
        parameters.keyPrefix = (0, helpers_js_1.bufferToHex)(deriveKeyResult.derivedKey.slice(0, keyPrefixLength));
    }
    // Return unsigned challenge if no HMAC secret is provided.
    if (!hmacSignatureSecret) {
        return {
            parameters: (0, helpers_js_1.sortKeys)(parameters),
        };
    }
    return signChallenge(hmacAlgorithm, parameters, deriveKeyResult?.derivedKey, hmacSignatureSecret, hmacKeySignatureSecret);
}
/**
 * Solves a challenge by brute-forcing counter values until the derived key
 * starts with the required prefix. Returns the solution or null on timeout/abort.
 */
async function solveChallenge(options) {
    const { challenge, controller, counterMode = 'uint32', counterStart = 0, counterStep = 1, deriveKey, timeout = 90_000, } = options;
    const { nonce, keyPrefix, salt } = challenge.parameters;
    const nonceBuf = (0, helpers_js_1.hexToBuffer)(nonce);
    const saltBuf = (0, helpers_js_1.hexToBuffer)(salt);
    const keyPrefixBuf = keyPrefix.length % 2 === 0 ? (0, helpers_js_1.hexToBuffer)(keyPrefix) : null;
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
            await (0, helpers_js_1.delay)(0);
            lastYield = performance.now();
        }
        // Check if the derived key matches the required prefix.
        if (keyPrefixBuf
            ? (0, helpers_js_1.bufferStartsWith)(derivedKey, keyPrefixBuf)
            : (0, helpers_js_1.bufferToHex)(derivedKey).startsWith(keyPrefix)) {
            derivedKeyHex = (0, helpers_js_1.bufferToHex)(derivedKey);
            break;
        }
        counter = counter + counterStep;
        iterations = iterations + 1;
    }
    return {
        counter,
        derivedKey: derivedKeyHex,
        time: (0, helpers_js_1.timeDuration)(start),
    };
}
/**
 * Solves a challenge using multiple Web Workers in parallel.
 * Each worker tests a different subset of counter values (interleaved by concurrency).
 * Automatically retries with fewer workers on out-of-memory errors.
 */
async function solveChallengeWorkers(options) {
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
async function signChallenge(algorithm, parameters, derivedKey, hmacSignatureSecret, hmacKeySignatureSecret) {
    if (derivedKey && hmacKeySignatureSecret) {
        parameters.keySignature = (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(algorithm, derivedKey, hmacKeySignatureSecret));
    }
    parameters = (0, helpers_js_1.sortKeys)(parameters);
    return {
        parameters,
        signature: (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(algorithm, JSON.stringify(parameters), hmacSignatureSecret)),
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
async function verifySolution(options) {
    const { challenge, counterMode, deriveKey, hmacAlgorithm = types_js_1.HmacAlgorithm.SHA_256, hmacKeySignatureSecret, hmacSignatureSecret, solution, } = options;
    const start = performance.now();
    // 1. Check expiration.
    if (challenge.parameters.expiresAt &&
        challenge.parameters.expiresAt < Date.now() / 1_000) {
        return {
            expired: true,
            invalidSignature: null,
            invalidSolution: null,
            time: (0, helpers_js_1.timeDuration)(start),
            verified: false,
        };
    }
    // 2. Signature parameter check.
    if (!challenge.signature) {
        return {
            expired: false,
            invalidSignature: true,
            invalidSolution: null,
            time: (0, helpers_js_1.timeDuration)(start),
            verified: false,
        };
    }
    // 3. Verify challenge signature to ensure parameters haven't been tampered with.
    const signatureCheck = (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(hmacAlgorithm, (0, helpers_js_1.canonicalJSON)(challenge.parameters), hmacSignatureSecret));
    const signatureVerified = (0, helpers_js_1.constantTimeEqual)(challenge.signature, signatureCheck);
    if (!signatureVerified) {
        return {
            expired: false,
            invalidSignature: true,
            invalidSolution: null,
            time: (0, helpers_js_1.timeDuration)(start),
            verified: false,
        };
    }
    // 4a. If a key signature exists, verify the derived key against it (faster path).
    if (challenge.parameters.keySignature && hmacKeySignatureSecret) {
        const derivedKeySignatureCheck = (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(hmacAlgorithm, (0, helpers_js_1.hexToBuffer)(solution.derivedKey), hmacKeySignatureSecret));
        const derivedKeySignatureValid = (0, helpers_js_1.constantTimeEqual)(challenge.parameters.keySignature, derivedKeySignatureCheck);
        return {
            expired: false,
            invalidSignature: false,
            invalidSolution: !derivedKeySignatureValid,
            time: (0, helpers_js_1.timeDuration)(start),
            verified: derivedKeySignatureValid,
        };
    }
    // 4b. Otherwise, re-derive the key from the solution's counter and compare.
    const nonceBuf = (0, helpers_js_1.hexToBuffer)(challenge.parameters.nonce);
    const saltBuf = (0, helpers_js_1.hexToBuffer)(challenge.parameters.salt);
    const { derivedKey } = await deriveKey(challenge.parameters, saltBuf, new PasswordBuffer(nonceBuf, counterMode).setCounter(solution.counter));
    const derivedKeyHex = (0, helpers_js_1.bufferToHex)(derivedKey);
    const invalidSolution = !(0, helpers_js_1.constantTimeEqual)(derivedKeyHex, solution.derivedKey);
    return {
        expired: false,
        invalidSignature: false,
        invalidSolution,
        time: (0, helpers_js_1.timeDuration)(start),
        verified: !invalidSolution && signatureVerified,
    };
}
