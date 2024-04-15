"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.solveChallengeWorkers = exports.solveChallenge = exports.verifySolution = exports.createChallenge = void 0;
const helpers_js_1 = require("./helpers.js");
const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG = 'SHA-256';
async function createChallenge(options) {
    const algorithm = options.algorithm || DEFAULT_ALG;
    const max = options.maxNumber || DEFAULT_MAX_NUMBER;
    const saltLength = options.saltLength || DEFAULT_SALT_LEN;
    const salt = options.salt || (0, helpers_js_1.ab2hex)((0, helpers_js_1.randomBytes)(saltLength));
    const number = options.number === void 0 ? (0, helpers_js_1.randomInt)(max) : options.number;
    const challenge = await (0, helpers_js_1.hash)(algorithm, salt + number);
    return {
        algorithm,
        challenge,
        max,
        salt,
        signature: await (0, helpers_js_1.hmac)(algorithm, challenge, options.hmacKey),
    };
}
exports.createChallenge = createChallenge;
async function verifySolution(payload, hmacKey) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
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
exports.verifySolution = verifySolution;
function solveChallenge(challenge, salt, algorithm = 'SHA-256', max = 1e6, start = 0) {
    const controller = new AbortController();
    const promise = new Promise((resolve, reject) => {
        const startTime = Date.now();
        const next = (n) => {
            if (controller.signal.aborted || n > max) {
                resolve(null);
            }
            else {
                hashChallenge(salt, n, algorithm)
                    .then((t) => {
                    if (t === challenge) {
                        resolve({
                            number: n,
                            took: Date.now() - startTime,
                        });
                    }
                    else {
                        next(n + 1);
                    }
                })
                    .catch(reject);
            }
        };
        next(start);
    });
    return {
        promise,
        controller,
    };
}
exports.solveChallenge = solveChallenge;
async function solveChallengeWorkers(workerScript, concurrency, challenge, salt, algorithm = 'SHA-256', max = 1e6, startNumber = 0) {
    const workers = [];
    if (concurrency < 1) {
        throw new Error('Wrong number of workers configured.');
    }
    if (concurrency > 16) {
        throw new Error('Too many workers. Max. 16 allowed workers.');
    }
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
exports.solveChallengeWorkers = solveChallengeWorkers;
async function hashChallenge(salt, num, algorithm) {
    return (0, helpers_js_1.ab2hex)(await crypto.subtle.digest(algorithm.toUpperCase(), helpers_js_1.encoder.encode(salt + num)));
}
exports.default = {
    createChallenge,
    verifySolution,
    solveChallenge,
    solveChallengeWorkers,
};
