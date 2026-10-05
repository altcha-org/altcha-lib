"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const node_crypto_1 = require("node:crypto");
const helpers_js_1 = require("../helpers.js");
const DIGESTS = {
    'SHA-256': 'sha256',
    'SHA-384': 'sha384',
    'SHA-512': 'sha512',
};
function getDigest(algorithm) {
    (0, helpers_js_1.assertAlgorithm)(algorithm, Object.keys(DIGESTS));
    return DIGESTS[algorithm];
}
async function deriveKey(parameters, salt, password) {
    const { algorithm, keyLength = 32 } = parameters;
    const iterations = Math.max(1, parameters.cost);
    let data = undefined;
    let derivedKey = undefined;
    for (let i = 0; i < iterations; i++) {
        if (i === 0) {
            data = (0, helpers_js_1.concatBuffers)(salt, password);
        }
        else {
            data = derivedKey;
        }
        derivedKey = (0, node_crypto_1.createHash)(getDigest(algorithm)).update(data).digest();
    }
    return {
        parameters: {},
        derivedKey: derivedKey.subarray(0, keyLength),
    };
}
