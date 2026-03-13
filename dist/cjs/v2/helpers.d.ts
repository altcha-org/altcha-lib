import type { HmacAlgorithm } from './types.js';
/** Checks if a buffer starts with the given prefix bytes. */
export declare function bufferStartsWith(buffer: Uint8Array, prefix: Uint8Array): boolean;
/** Converts a byte buffer to a lowercase hex string. */
export declare function bufferToHex(buffer: Uint8Array | ArrayBuffer): string;
/** Returns a canonical (sorted-key) JSON string for consistent hashing/signing. */
export declare function canonicalJSON(obj: unknown): string;
/** Concatenates two Uint8Arrays into a new buffer. */
export declare function concatBuffers(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer>;
/** Converts a hex string to a Uint8Array. Throws if the string has odd length. */
export declare function hexToBuffer(hex: string): Uint8Array;
/** Checks if two strings are equal in constant time. */
export declare function constantTimeEqual(a: string, b: string): boolean;
/** Yields to the event loop after the given milliseconds. */
export declare function delay(ms: number): Promise<void>;
/** Generate a SHA hash */
export declare function hash(algorithm: string, data: ArrayBuffer | string): Promise<Uint8Array>;
/** Computes an HMAC signature using the Web Crypto API. */
export declare function hmac(algorithm: HmacAlgorithm, data: string | Uint8Array, keyStr: string): Promise<Uint8Array>;
/** Inject CSS tag into the document */
export declare function injectCss(css: string, id?: string): void;
/** Generates a random integer between the specified minimum and maximum values (inclusive). */
export declare function randomInt(max: number, min?: number): number;
/** Recursively sorts object keys alphabetically for deterministic serialization. */
export declare function sortKeys<T = unknown>(obj: T): T;
/** Returns elapsed time in milliseconds since `start`, rounded to one decimal. */
export declare function timeDuration(start: number): number;
