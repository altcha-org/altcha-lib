import type { Algorithm } from './types.js';
export declare function ab2hex(ab: ArrayBuffer | Uint8Array): string;
export declare function hash(algorithm: Algorithm, str: string): Promise<string>;
export declare function hmac(algorithm: Algorithm, str: string, secret: string): Promise<string>;
export declare function randomBytes(length: number): Uint8Array;
export declare function randomInt(max: number): number;
