"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createChallenge = createChallenge;
exports.extractParams = extractParams;
exports.verifySolution = verifySolution;
exports.verifyFieldsHash = verifyFieldsHash;
exports.verifyServerSignature = verifyServerSignature;
exports.solveChallenge = solveChallenge;
exports.solveChallengeWorkers = solveChallengeWorkers;
const helpers_js_1 = require("./helpers.js");
const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG = 'SHA-256';
/**
 * Creates a challenge for the client to solve.
 *
 * @param {ChallengeOptions} options - Options for creating the challenge.
 * @returns {Promise<Challenge>} The created challenge.
 */
async function createChallenge(options) {
    const algorithm = options.algorithm || DEFAULT_ALG;
    const maxnumber = options.maxnumber || options.maxNumber || DEFAULT_MAX_NUMBER;
    const saltLength = options.saltLength || DEFAULT_SALT_LEN;
    const params = new URLSearchParams(options.params);
    if (options.expires) {
        params.set('expires', String(Math.floor(options.expires.getTime() / 1000)));
    }
    let salt = options.salt || (0, helpers_js_1.ab2hex)((0, helpers_js_1.randomBytes)(saltLength));
    // params.size doesn't work with Node 16
    if (Object.keys(Object.fromEntries(params)).length) {
        salt = salt + '?' + params.toString();
    }
    const number = options.number === undefined ? (0, helpers_js_1.randomInt)(maxnumber) : options.number;
    const challenge = await (0, helpers_js_1.hashHex)(algorithm, salt + number);
    return {
        algorithm,
        challenge,
        maxnumber,
        salt,
        signature: await (0, helpers_js_1.hmacHex)(algorithm, challenge, options.hmacKey),
    };
}
/**
 * Extracts parameters from the payload.
 *
 * @param {string | Payload | Challenge} payload - The payload from which to extract parameters.
 * @returns {Record<string, string>} The extracted parameters.
 */
function extractParams(payload) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
    }
    return Object.fromEntries(new URLSearchParams(payload?.salt?.split('?')?.[1] || ''));
}
/**
 * Verifies the solution provided by the client.
 *
 * @param {string | Payload} payload - The payload to verify.
 * @param {string} hmacKey - The HMAC key used for verification.
 * @param {boolean} [checkExpires=true] - Whether to check if the challenge has expired.
 * @returns {Promise<boolean>} Whether the solution is valid.
 */
async function verifySolution(payload, hmacKey, checkExpires = true) {
    if (typeof payload === 'string') {
        try {
            payload = JSON.parse(atob(payload));
        }
        catch {
            return false;
        }
    }
    const params = extractParams(payload);
    const expires = params.expires || params.expire;
    if (checkExpires && expires) {
        const date = new Date(parseInt(expires, 10) * 1000);
        if (Number.isNaN(date.getTime()) || date.getTime() < Date.now()) {
            return false;
        }
    }
    const check = await createChallenge({
        algorithm: payload.algorithm,
        hmacKey,
        number: payload.number,
        salt: payload.salt,
    });
    return (check.challenge === payload.challenge &&
        check.signature === payload.signature);
}
/**
 * Verifies the hash of form fields.
 *
 * @param {FormData | Record<string, unknown>} formData - The form data to verify.
 * @param {string[]} fields - The fields to include in the hash.
 * @param {string} fieldsHash - The expected hash of the fields.
 * @param {string} [algorithm=DEFAULT_ALG] - The hash algorithm to use.
 * @returns {Promise<boolean>} Whether the fields hash is valid.
 */
async function verifyFieldsHash(formData, fields, fieldsHash, algorithm = DEFAULT_ALG) {
    const data = formData instanceof FormData ? Object.fromEntries(formData) : formData;
    const lines = [];
    for (const field of fields) {
        lines.push(String(data[field] || ''));
    }
    return (await (0, helpers_js_1.hashHex)(algorithm, lines.join('\n'))) === fieldsHash;
}
/**
 * Verifies the server's signature.
 *
 * @param {string | ServerSignaturePayload} payload - The payload to verify.
 * @param {string} hmacKey - The HMAC key used for verification.
 * @returns {Promise<{verificationData: ServerSignatureVerificationData | null, verified: boolean}>} The verification result.
 */
async function verifyServerSignature(payload, hmacKey) {
    if (typeof payload === 'string') {
        try {
            payload = JSON.parse(atob(payload));
        }
        catch {
            return {
                verificationData: null,
                verified: false,
            };
        }
    }
    const signature = await (0, helpers_js_1.hmacHex)(payload.algorithm, await (0, helpers_js_1.hash)(payload.algorithm, payload.verificationData), hmacKey);
    let verificationData = null;
    try {
        const params = new URLSearchParams(payload.verificationData);
        verificationData = {
            ...Object.fromEntries(params),
            expire: parseInt(params.get('expire') || '0', 10),
            fields: params.get('fields')?.split(','),
            reasons: params.get('reasons')?.split(','),
            score: params.get('score')
                ? parseFloat(params.get('score') || '0')
                : undefined,
            time: parseInt(params.get('time') || '0', 10),
            verified: params.get('verified') === 'true',
        };
    }
    catch {
        // noop
    }
    return {
        verificationData,
        verified: payload.verified === true &&
            verificationData?.verified === true &&
            verificationData.expire > Math.floor(Date.now() / 1000) &&
            payload.signature === signature,
    };
}
/**
 * Solves a challenge by brute force.
 *
 * @param {string} challenge - The challenge to solve.
 * @param {string} salt - The salt used in the challenge.
 * @param {string} [algorithm='SHA-256'] - The hash algorithm used.
 * @param {number} [max=1e6] - The maximum number to try.
 * @param {number} [start=0] - The starting number.
 * @returns {{promise: Promise<Solution | null>, controller: AbortController}} The solution promise and abort controller.
 */
function solveChallenge(challenge, salt, algorithm = 'SHA-256', max = 1e6, start = 0) {
    const controller = new AbortController();
    const startTime = Date.now();
    const fn = async () => {
        for (let n = start; n <= max; n += 1) {
            if (controller.signal.aborted) {
                return null;
            }
            const t = await (0, helpers_js_1.hashHex)(algorithm, salt + n);
            if (t === challenge) {
                return {
                    number: n,
                    took: Date.now() - startTime,
                };
            }
        }
        return null;
    };
    return {
        promise: fn(),
        controller,
    };
}
/**
 * Solves a challenge using web workers for parallel computation.
 *
 * @param {string | URL | (() => Worker)} workerScript - The worker script or function to create a worker.
 * @param {number} concurrency - The number of workers to use.
 * @param {string} challenge - The challenge to solve.
 * @param {string} salt - The salt used in the challenge.
 * @param {string} [algorithm='SHA-256'] - The hash algorithm used.
 * @param {number} [max=1e6] - The maximum number to try.
 * @param {number} [startNumber=0] - The starting number.
 * @returns {Promise<Solution | null>} The solution, or null if not found.
 */
async function solveChallengeWorkers(workerScript, concurrency, challenge, salt, algorithm = 'SHA-256', max = 1e6, startNumber = 0) {
    const workers = [];
    concurrency = Math.max(1, Math.min(16, concurrency));
    for (let i = 0; i < concurrency; i++) {
        if (typeof workerScript === 'function') {
            workers.push(workerScript());
        }
        else {
            workers.push(new Worker(workerScript, {
                type: 'module',
            }));
        }
    }
    const step = Math.ceil(max / concurrency);
    const solutions = await Promise.all(workers.map((worker, i) => {
        const start = startNumber + i * step;
        return new Promise((resolve) => {
            worker.addEventListener('message', (message) => {
                if (message.data) {
                    for (const w of workers) {
                        if (w !== worker) {
                            w.postMessage({ type: 'abort' });
                        }
                    }
                }
                resolve(message.data);
            });
            worker.postMessage({
                payload: {
                    algorithm,
                    challenge,
                    max: start + step,
                    salt,
                    start,
                },
                type: 'work',
            });
        });
    }));
    for (const worker of workers) {
        worker.terminate();
    }
    return solutions.find((solution) => !!solution) || null;
}
exports.default = {
    createChallenge,
    extractParams,
    solveChallenge,
    solveChallengeWorkers,
    verifyFieldsHash,
    verifyServerSignature,
    verifySolution,
};
