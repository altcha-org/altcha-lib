import { ab2hex, encoder, hash, hmac, randomBytes, randomInt, } from './helpers.js';
const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG = 'SHA-256';
export async function createChallenge(options) {
    const algorithm = options.algorithm || DEFAULT_ALG;
    const max = options.maxNumber || DEFAULT_MAX_NUMBER;
    const saltLength = options.saltLength || DEFAULT_SALT_LEN;
    const salt = options.salt || ab2hex(randomBytes(saltLength));
    const number = options.number === void 0 ? randomInt(max) : options.number;
    const challenge = await hash(algorithm, salt + number);
    return {
        algorithm,
        challenge,
        max,
        salt,
        signature: await hmac(algorithm, challenge, options.hmacKey),
    };
}
export async function verifySolution(payload, hmacKey) {
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
export function solveChallenge(challenge, salt, algorithm = 'SHA-256', max = 1e6, start = 0) {
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
export async function solveChallengeWorkers(workerScript, concurrency, challenge, salt, algorithm = 'SHA-256', max = 1e6, startNumber = 0) {
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
async function hashChallenge(salt, num, algorithm) {
    return ab2hex(await crypto.subtle.digest(algorithm.toUpperCase(), encoder.encode(salt + num)));
}
export default {
    createChallenge,
    verifySolution,
    solveChallenge,
    solveChallengeWorkers,
};
