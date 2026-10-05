import { scrypt } from 'node:crypto';
import { promisify } from 'node:util';
import { assertAlgorithm, assertPositiveInteger } from '../helpers.js';
const scryptAsync = promisify(scrypt);
export async function deriveKey(parameters, salt, password) {
    assertAlgorithm(parameters.algorithm, ['SCRYPT']);
    assertPositiveInteger('memoryCost', parameters.memoryCost);
    return {
        parameters: {},
        derivedKey: await scryptAsync(password, salt, parameters.keyLength, {
            blockSize: parameters.memoryCost,
            cost: parameters.cost,
            maxmem: 2 * 128 * parameters.cost * parameters.memoryCost,
            parallelization: parameters.parallelism || 1,
        }),
    };
}
