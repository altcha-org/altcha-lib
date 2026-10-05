"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const helpers_js_1 = require("../../helpers.js");
async function deriveKey(parameters, salt, password) {
    const { algorithm, cost, keyLength = 32 } = parameters;
    (0, helpers_js_1.assertAlgorithm)(algorithm, [
        'PBKDF2/SHA-256',
        'PBKDF2/SHA-384',
        'PBKDF2/SHA-512',
    ]);
    const passwordKey = await crypto.subtle.importKey('raw', password, { name: 'PBKDF2' }, false, ['deriveBits']);
    // deriveBits supports any key length, unlike deriving an AES key (16, 24 or 32 bytes only).
    const derivedBits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: salt,
        iterations: cost,
        hash: algorithm.slice('PBKDF2/'.length),
    }, passwordKey, keyLength * 8);
    return {
        parameters: {},
        derivedKey: new Uint8Array(derivedBits),
    };
}
