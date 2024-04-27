import type { Algorithm } from './types.ts';

export const encoder = new TextEncoder();

export function ab2hex(ab: ArrayBuffer | Uint8Array) {
  return [...new Uint8Array(ab)]
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

export async function hash(algorithm: Algorithm, data: ArrayBuffer | string) {
  return crypto.subtle.digest(
    algorithm.toUpperCase(),
    typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data)
  );
}

export async function hashHex(
  algorithm: Algorithm,
  data: ArrayBuffer | string
) {
  return ab2hex(await hash(algorithm, data));
}

export async function hmac(
  algorithm: Algorithm,
  data: ArrayBuffer | string,
  secret: string
) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    {
      name: 'HMAC',
      hash: algorithm,
    },
    false,
    ['sign', 'verify']
  );
  return crypto.subtle.sign(
    'HMAC',
    key,
    typeof data === 'string' ? encoder.encode(data) : new Uint8Array(data)
  );
}

export async function hmacHex(
  algorithm: Algorithm,
  data: ArrayBuffer | string,
  secret: string
) {
  return ab2hex(await hmac(algorithm, data, secret));
}

export function randomBytes(length: number) {
  const ab = new Uint8Array(length);
  crypto.getRandomValues(ab);
  return ab;
}

export function randomInt(max: number) {
  const ab = new Uint32Array(1);
  crypto.getRandomValues(ab);
  const randomNumber = ab[0] / (0xffffffff + 1);
  return Math.floor(randomNumber * max + 1);
}
