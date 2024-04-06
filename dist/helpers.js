import './crypto.js';
export const encoder = new TextEncoder();
export function ab2hex(ab) {
    return [...new Uint8Array(ab)]
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');
}
export async function hash(algorithm, str) {
    return ab2hex(await crypto.subtle.digest(algorithm.toUpperCase(), encoder.encode(str)));
}
export async function hmac(algorithm, str, secret) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), {
        name: 'HMAC',
        hash: algorithm,
    }, false, ['sign', 'verify']);
    return ab2hex(await crypto.subtle.sign('HMAC', key, encoder.encode(str)));
}
export function randomBytes(length) {
    const ab = new Uint8Array(length);
    crypto.getRandomValues(ab);
    return ab;
}
export function randomInt(max) {
    const ab = new Uint32Array(1);
    crypto.getRandomValues(ab);
    const randomNumber = ab[0] / (0xffffffff + 1);
    return Math.floor(randomNumber * max + 1);
}
