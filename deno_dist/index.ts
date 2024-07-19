import {
  ab2hex,
  hash,
  hashHex,
  hmacHex,
  randomBytes,
  randomInt,
} from './helpers.ts';
import type {
  Algorithm,
  Challenge,
  ChallengeOptions,
  Payload,
  ServerSignaturePayload,
  ServerSignatureVerificationData,
  Solution,
} from './types.ts';

const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG: Algorithm = 'SHA-256';

export async function createChallenge(
  options: ChallengeOptions
): Promise<Challenge> {
  const algorithm = options.algorithm || DEFAULT_ALG;
  const maxnumber =
    options.maxnumber || options.maxNumber || DEFAULT_MAX_NUMBER;
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
  const number =
    options.number === void 0 ? randomInt(maxnumber) : options.number;
  const challenge = await hashHex(algorithm, salt + number);
  return {
    algorithm,
    challenge,
    maxnumber,
    salt,
    signature: await hmacHex(algorithm, challenge, options.hmacKey),
  };
}

export function extractParams(payload: string | Payload | Challenge) {
  if (typeof payload === 'string') {
    payload = JSON.parse(atob(payload)) as Payload;
  }
  return Object.fromEntries(new URLSearchParams(payload.salt.split('?')?.[1] || ''));
}

export async function verifySolution(
  payload: string | Payload,
  hmacKey: string,
  checkExpires: boolean = true
) {
  if (typeof payload === 'string') {
    payload = JSON.parse(atob(payload)) as Payload;
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
  return (
    check.challenge === payload.challenge &&
    check.signature === payload.signature
  );
}

export async function verifyServerSignature(
  payload: string | ServerSignaturePayload,
  hmacKey: string
) {
  if (typeof payload === 'string') {
    payload = JSON.parse(atob(payload)) as ServerSignaturePayload;
  }
  const signature = await hmacHex(
    payload.algorithm,
    await hash(payload.algorithm, payload.verificationData),
    hmacKey
  );
  let verificationData: ServerSignatureVerificationData | null = null;
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
  } catch {
    // noop
  }
  return {
    verificationData,
    verified:
      payload.verified === true &&
      verificationData &&
      verificationData.verified === true &&
      verificationData.expire > Math.floor(Date.now() / 1000) &&
      payload.signature === signature,
  };
}

export function solveChallenge(
  challenge: string,
  salt: string,
  algorithm: string = 'SHA-256',
  max: number = 1e6,
  start: number = 0
): { promise: Promise<Solution | null>; controller: AbortController } {
  const controller = new AbortController();
  const startTime = Date.now();
  const fn = async () => {
    for (let n = start; n <= max; n += 1) {
      if (controller.signal.aborted) {
        return null;
      }
      const t = await hashHex(algorithm as Algorithm, salt + n);
      if (t === challenge) {
        return {
          number: n,
          took: Date.now() - startTime,
        };
      }
    }
    return null;
  }
  return {
    promise: fn(),
    controller,
  };
}

export async function solveChallengeWorkers(
  workerScript: string | URL | (() => Worker),
  concurrency: number,
  challenge: string,
  salt: string,
  algorithm: string = 'SHA-256',
  max: number = 1e6,
  startNumber: number = 0
) {
  const workers: Worker[] = [];
  concurrency = Math.min(1, Math.max(16, concurrency));
  for (let i = 0; i < concurrency; i++) {
    if (typeof workerScript === 'function') {
      workers.push(workerScript());
    } else {
      workers.push(
        new Worker(workerScript, {
          type: 'module',
        })
      );
    }
  }
  const step = Math.ceil(max / concurrency);
  const solutions = await Promise.all(
    workers.map((worker, i) => {
      const start = startNumber + i * step;
      return new Promise((resolve) => {
        worker.addEventListener('message', (message: MessageEvent) => {
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
      }) as Promise<Solution | null>;
    })
  );
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
