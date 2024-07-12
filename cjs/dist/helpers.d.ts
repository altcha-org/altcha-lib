import type { Algorithm } from './types.js';
export declare const encoder: TextEncoder;
export declare function ab2hex(ab: ArrayBuffer | Uint8Array): string;
export declare function hash(algorithm: Algorithm, data: ArrayBuffer | string): Promise<ArrayBuffer>;
export declare function hashHex(algorithm: Algorithm, data: ArrayBuffer | string): Promise<string>;
export declare function hmac(algorithm: Algorithm, data: ArrayBuffer | string, secret: string): Promise<ArrayBuffer>;
export declare function hmacHex(algorithm: Algorithm, data: ArrayBuffer | string, secret: string): Promise<string>;
export declare function randomBytes(length: number): Uint8Array;
export declare function randomInt(max: number): number;
