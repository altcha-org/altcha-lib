import { type CreateChallengeOptions, type DeriveKeyFunction } from './types.js';
export declare function deobfuscate(obfuscatedData: string, options?: {
    concurrency?: number;
    createWorker?: (algorithm: string) => Worker | Promise<Worker>;
    deriveKey?: DeriveKeyFunction;
}): Promise<string>;
export declare function obfuscate(str: string, options?: Partial<CreateChallengeOptions> & {
    counterMax?: number;
    counterMin?: number;
    deriveKey?: DeriveKeyFunction;
}): Promise<string>;
