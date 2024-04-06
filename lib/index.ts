import {
  ab2hex,
  encoder,
  hash,
  hmac,
  randomBytes,
  randomInt,
} from './helpers.js';
import type {
  Algorithm,
  Challenge,
  ChallengeOptions,
  Payload,
  Solution,
} from './types.js';

const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG: Algorithm = 'SHA-256';

export async function createChallenge(
  options: ChallengeOptions
): Promise<Challenge> {
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

export async function verifySolution(
  payload: string | Payload,
  hmacKey: string
) {
  if (typeof payload === 'string') {
    payload = JSON.parse(atob(payload)) as Payload;
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

export function solveChallenge(
  challenge: string,
  salt: string,
  algorithm: string = 'SHA-256',
  max: number = 1e6,
  start: number = 0
): { promise: Promise<Solution | null>; controller: AbortController } {
  const controller = new AbortController();
  const promise = new Promise((resolve, reject) => {
    const startTime = Date.now();
    const next = (n: number) => {
      if (controller.signal.aborted || n > max) {
        resolve(null);
      } else {
        hashChallenge(salt, n, algorithm)
          .then((t) => {
            if (t === challenge) {
              resolve({
                number: n,
                took: Date.now() - startTime,
              });
            } else {
              next(n + 1);
            }
          })
          .catch(reject);
      }
    };
    next(start);
  }) as Promise<Solution | null>;
  return {
    promise,
    controller,
  };
}

export async function solveChallengeWorkers(
  workerScript: string | URL,
  concurrency: number,
  challenge: string,
  salt: string,
  algorithm: string = 'SHA-256',
  max: number = 1e6,
  startNumber: number = 0
) {
  const workers: Worker[] = [];
  if (concurrency < 1) {
    throw new Error('Wrong number of workers configured.');
  }
  if (concurrency > 16) {
    throw new Error('Too many workers. Max. 16 allowed workers.');
  }
  for (let i = 0; i < concurrency; i++) {
    workers.push(
      new Worker(workerScript, {
        type: 'module',
      })
    );
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

async function hashChallenge(salt: string, num: number, algorithm: string) {
  return ab2hex(
    await crypto.subtle.digest(
      algorithm.toUpperCase(),
      encoder.encode(salt + num)
    )
  );
}
