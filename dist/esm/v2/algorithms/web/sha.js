import { assertAlgorithm, concatBuffers } from '../../helpers.js';
export async function deriveKey(parameters, salt, password) {
    const { algorithm, keyLength = 32 } = parameters;
    assertAlgorithm(algorithm, ['SHA-256', 'SHA-384', 'SHA-512']);
    const iterations = Math.max(1, parameters.cost);
    let derivedKey = concatBuffers(salt, password);
    // Each round hashes the full previous digest; truncate to keyLength only at the end,
    // matching the Node implementation and the other language ports.
    for (let i = 0; i < iterations; i++) {
        derivedKey = new Uint8Array(await crypto.subtle.digest(algorithm, derivedKey));
    }
    return {
        parameters: {},
        derivedKey: derivedKey.slice(0, keyLength),
    };
}
