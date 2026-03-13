import type { Algorithm } from './types.js';
export declare const encoder: TextEncoder;
/**
 * Converts an ArrayBuffer or Uint8Array to a hexadecimal string.
 *
 * @param ab - The ArrayBuffer or Uint8Array to convert.
 * @returns The hexadecimal string representation of the input.
 */
export declare function ab2hex(ab: ArrayBuffer | Uint8Array): string;
/**
 * Generates a cryptographic hash using the specified algorithm.
 *
 * @param algorithm - The cryptographic hash algorithm to use (e.g., 'SHA-256').
 * @param data - The data to hash, either as a string or ArrayBuffer.
 * @returns A Promise that resolves to the computed hash as an ArrayBuffer.
 */
export declare function hash(algorithm: Algorithm, data: ArrayBuffer | string): Promise<ArrayBuffer>;
/**
 * Generates a cryptographic hash using the specified algorithm and returns it as a hexadecimal string.
 *
 * @param algorithm - The cryptographic hash algorithm to use (e.g., 'SHA-256').
 * @param data - The data to hash, either as a string or ArrayBuffer.
 * @returns A Promise that resolves to the computed hash as a hexadecimal string.
 */
export declare function hashHex(algorithm: Algorithm, data: ArrayBuffer | string): Promise<string>;
/**
 * Generates an HMAC using the specified algorithm and secret key.
 *
 * @param algorithm - The cryptographic hash algorithm to use for HMAC (e.g., 'SHA-256').
 * @param data - The data to sign, either as a string or ArrayBuffer.
 * @param secret - The secret key to use for HMAC.
 * @returns A Promise that resolves to the computed HMAC as an ArrayBuffer.
 */
export declare function hmac(algorithm: Algorithm, data: ArrayBuffer | string, secret: string): Promise<ArrayBuffer>;
/**
 * Generates an HMAC using the specified algorithm and secret key, and returns it as a hexadecimal string.
 *
 * @param algorithm - The cryptographic hash algorithm to use for HMAC (e.g., 'SHA-256').
 * @param data - The data to sign, either as a string or ArrayBuffer.
 * @param secret - The secret key to use for HMAC.
 * @returns A Promise that resolves to the computed HMAC as a hexadecimal string.
 */
export declare function hmacHex(algorithm: Algorithm, data: ArrayBuffer | string, secret: string): Promise<string>;
/**
 * Generates a random sequence of bytes of the specified length.
 *
 * @param length - The number of random bytes to generate.
 * @returns A Uint8Array containing the random bytes.
 */
export declare function randomBytes(length: number): Uint8Array;
/**
 * Generates a random integer between 1 and the specified maximum value (inclusive).
 *
 * @param max - The maximum value for the random integer.
 * @returns A random integer between 1 and the specified max value.
 */
export declare function randomInt(max: number): number;
