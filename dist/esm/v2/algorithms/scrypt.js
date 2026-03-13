import { scrypt } from 'node:crypto';
import { promisify } from 'node:util';
const scryptAsync = promisify(scrypt);
export async function deriveKey(parameters, salt, password) {
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
