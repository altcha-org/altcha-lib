import { createHash } from 'node:crypto';
import { concatBuffers } from '../helpers.js';
function getDigest(algorithm) {
    switch (algorithm) {
        case 'SHA-512':
            return 'sha512';
        case 'SHA-384':
            return 'sha384';
        case 'SHA-256':
        default:
            return 'sha256';
    }
}
export async function deriveKey(parameters, salt, password) {
    const { algorithm, keyLength = 32 } = parameters;
    const iterations = Math.max(1, parameters.cost);
    let data = undefined;
    let derivedKey = undefined;
    for (let i = 0; i < iterations; i++) {
        if (i === 0) {
            data = concatBuffers(salt, password);
        }
        else {
            data = derivedKey;
        }
        derivedKey = createHash(getDigest(algorithm)).update(data).digest();
    }
    return {
        parameters: {},
        derivedKey: derivedKey.subarray(0, keyLength),
    };
}
