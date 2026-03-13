import { concatBuffers } from '../../helpers.js';
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
        derivedKey = new Uint8Array((await crypto.subtle.digest(algorithm, data)).slice(0, keyLength));
    }
    return {
        parameters: {},
        derivedKey: derivedKey,
    };
}
