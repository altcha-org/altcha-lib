"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const helpers_js_1 = require("../../helpers.js");
async function deriveKey(parameters, salt, password) {
    const { algorithm, keyLength = 32 } = parameters;
    (0, helpers_js_1.assertAlgorithm)(algorithm, ['SHA-256', 'SHA-384', 'SHA-512']);
    const iterations = Math.max(1, parameters.cost);
    let derivedKey = (0, helpers_js_1.concatBuffers)(salt, password);
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
