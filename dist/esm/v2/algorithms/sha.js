import { createHash } from 'node:crypto';
import { assertAlgorithm, concatBuffers } from '../helpers.js';
const DIGESTS = {
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
    'SHA-512': 'sha512',
};
function getDigest(algorithm) {
    assertAlgorithm(algorithm, Object.keys(DIGESTS));
    return DIGESTS[algorithm];
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
