import { ab2hex, hash, hashHex, hmacHex, randomBytes, randomInt, } from './helpers.js';
const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG = 'SHA-256';
export async function createChallenge(options) {
    const algorithm = options.algorithm || DEFAULT_ALG;
    const maxnumber = options.maxnumber || options.maxNumber || DEFAULT_MAX_NUMBER;
    const saltLength = options.saltLength || DEFAULT_SALT_LEN;
    const params = new URLSearchParams(options.params);
    if (options.expires) {
        params.set('expires', String(Math.floor(options.expires.getTime() / 1000)));
    }
    let salt = options.salt || ab2hex(randomBytes(saltLength));
    // params.size doesn't work with Node 16
    if (Object.keys(Object.fromEntries(params)).length) {
        salt = salt + '?' + params.toString();
    }
    const number = options.number === void 0 ? randomInt(maxnumber) : options.number;
    const challenge = await hashHex(algorithm, salt + number);
    return {
        algorithm,
        challenge,
        maxnumber,
        salt,
        signature: await hmacHex(algorithm, challenge, options.hmacKey),
    };
}
export function extractParams(payload) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
    }
    return Object.fromEntries(new URLSearchParams(payload.salt.split('?')?.[1] || ''));
}
export async function verifySolution(payload, hmacKey, checkExpires = true) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
    }
    const params = extractParams(payload);
    const expires = params.expires || params.expire;
    if (checkExpires && expires) {
        const date = new Date(parseInt(expires, 10) * 1000);
        if (!isNaN(date.getTime()) && date.getTime() < Date.now()) {
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
export async function verifyServerSignature(payload, hmacKey) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
    }
    const signature = await hmacHex(payload.algorithm, await hash(payload.algorithm, payload.verificationData), hmacKey);
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
                : void 0,
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
            verificationData &&
            verificationData.verified === true &&
            verificationData.expire > Math.floor(Date.now() / 1000) &&
            payload.signature === signature,
    };
}
export function solveChallenge(challenge, salt, algorithm = 'SHA-256', max = 1e6, start = 0) {
    const controller = new AbortController();
    const startTime = Date.now();
    const fn = async () => {
        for (let n = start; n <= max; n += 1) {
            if (controller.signal.aborted) {
                return null;
            }
            const t = await hashHex(algorithm, salt + n);
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
export default {
    createChallenge,
    extractParams,
    solveChallenge,
    solveChallengeWorkers,
    verifyServerSignature,
    verifySolution,
};
