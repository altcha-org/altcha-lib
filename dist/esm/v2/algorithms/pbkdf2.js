import { pbkdf2 } from 'node:crypto';
import { promisify } from 'node:util';
const pbkdf2Async = promisify(pbkdf2);
function getDigest(algorithm) {
    switch (algorithm) {
        case 'PBKDF2/SHA-512':
            return 'sha512';
        case 'PBKDF2/SHA-384':
            return 'sha384';
        case 'PBKDF2/SHA-256':
        default:
            return 'sha256';
    }
}
export async function deriveKey(parameters, salt, password) {
    return {
        parameters: {},
        derivedKey: await pbkdf2Async(password, salt, parameters.cost, parameters.keyLength, getDigest(parameters.algorithm)),
    };
}
