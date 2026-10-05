import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
import { assertAlgorithm } from '../helpers.js';
const pbkdf2Async = promisify(pbkdf2);
const DIGESTS = {
    'PBKDF2/SHA-256': 'sha256',
    'PBKDF2/SHA-384': 'sha384',
    'PBKDF2/SHA-512': 'sha512',
};
function getDigest(algorithm) {
    assertAlgorithm(algorithm, Object.keys(DIGESTS));
    return DIGESTS[algorithm];
}
export async function deriveKey(parameters, salt, password) {
    return {
        parameters: {},
        derivedKey: await pbkdf2Async(password, salt, parameters.cost, parameters.keyLength, getDigest(parameters.algorithm)),
    };
}
