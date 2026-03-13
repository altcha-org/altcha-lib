"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encoder = void 0;
exports.ab2hex = ab2hex;
exports.hash = hash;
exports.hashHex = hashHex;
exports.hmac = hmac;
exports.hmacHex = hmacHex;
exports.randomBytes = randomBytes;
exports.randomInt = randomInt;
// Create a TextEncoder instance to convert strings to UTF-8 byte arrays.
exports.encoder = new TextEncoder();
/**
 * Converts an ArrayBuffer or Uint8Array to a hexadecimal string.
 *
 * @param ab - The ArrayBuffer or Uint8Array to convert.
 * @returns The hexadecimal string representation of the input.
 */
function ab2hex(ab) {
    return [...new Uint8Array(ab)]
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');
}
/**
 * Generates a cryptographic hash using the specified algorithm.
 *
 * @param algorithm - The cryptographic hash algorithm to use (e.g., 'SHA-256').
 * @param data - The data to hash, either as a string or ArrayBuffer.
 * @returns A Promise that resolves to the computed hash as an ArrayBuffer.
 */
async function hash(algorithm, data) {
    return crypto.subtle.digest(algorithm.toUpperCase(), typeof data === 'string' ? exports.encoder.encode(data) : new Uint8Array(data));
}
/**
 * Generates a cryptographic hash using the specified algorithm and returns it as a hexadecimal string.
 *
 * @param algorithm - The cryptographic hash algorithm to use (e.g., 'SHA-256').
 * @param data - The data to hash, either as a string or ArrayBuffer.
 * @returns A Promise that resolves to the computed hash as a hexadecimal string.
 */
async function hashHex(algorithm, data) {
    return ab2hex(await hash(algorithm, data));
}
/**
 * Generates an HMAC using the specified algorithm and secret key.
 *
 * @param algorithm - The cryptographic hash algorithm to use for HMAC (e.g., 'SHA-256').
 * @param data - The data to sign, either as a string or ArrayBuffer.
 * @param secret - The secret key to use for HMAC.
 * @returns A Promise that resolves to the computed HMAC as an ArrayBuffer.
 */
async function hmac(algorithm, data, secret) {
    const key = await crypto.subtle.importKey('raw', exports.encoder.encode(secret), {
        name: 'HMAC',
        hash: algorithm,
    }, false, ['sign', 'verify']);
    return crypto.subtle.sign('HMAC', key, typeof data === 'string' ? exports.encoder.encode(data) : new Uint8Array(data));
}
/**
 * Generates an HMAC using the specified algorithm and secret key, and returns it as a hexadecimal string.
 *
 * @param algorithm - The cryptographic hash algorithm to use for HMAC (e.g., 'SHA-256').
 * @param data - The data to sign, either as a string or ArrayBuffer.
 * @param secret - The secret key to use for HMAC.
 * @returns A Promise that resolves to the computed HMAC as a hexadecimal string.
 */
async function hmacHex(algorithm, data, secret) {
    return ab2hex(await hmac(algorithm, data, secret));
}
/**
 * Generates a random sequence of bytes of the specified length.
 *
 * @param length - The number of random bytes to generate.
 * @returns A Uint8Array containing the random bytes.
 */
function randomBytes(length) {
    const ab = new Uint8Array(length);
    crypto.getRandomValues(ab);
    return ab;
}
/**
 * Generates a random integer between 1 and the specified maximum value (inclusive).
 *
 * @param max - The maximum value for the random integer.
 * @returns A random integer between 1 and the specified max value.
 */
function randomInt(max) {
    const ab = new Uint32Array(1);
    crypto.getRandomValues(ab);
    const randomNumber = ab[0] / (0xffffffff + 1);
    return Math.floor(randomNumber * max + 1);
}
