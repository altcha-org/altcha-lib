import { ab2hex, hash, hmac, randomBytes, randomInt } from './helpers.js';
import type {
  Algorithm,
  Challenge,
  ChallengeOptions,
  Payload,
} from './types.js';

const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG: Algorithm = 'SHA-256';

export async function createChallenge(
  options: ChallengeOptions
): Promise<Challenge> {
  const algorithm = options.algorithm || DEFAULT_ALG;
  const maxNumber = options.maxNumber || DEFAULT_MAX_NUMBER;
  const saltLength = options.saltLength || DEFAULT_SALT_LEN;
  const salt = options.salt || ab2hex(randomBytes(saltLength));
  const number =
    options.number === void 0 ? randomInt(maxNumber) : options.number;
  const challenge = await hash(algorithm, salt + number);
  return {
    algorithm,
    challenge,
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
