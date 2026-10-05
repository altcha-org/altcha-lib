"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const node_crypto_1 = require("node:crypto");
const node_util_1 = require("node:util");
const helpers_js_1 = require("../helpers.js");
const pbkdf2Async = (0, node_util_1.promisify)(node_crypto_1.pbkdf2);
const DIGESTS = {
    'PBKDF2/SHA-256': 'sha256',
    'PBKDF2/SHA-384': 'sha384',
    'PBKDF2/SHA-512': 'sha512',
};
function getDigest(algorithm) {
    (0, helpers_js_1.assertAlgorithm)(algorithm, Object.keys(DIGESTS));
    return DIGESTS[algorithm];
}
async function deriveKey(parameters, salt, password) {
    return {
        parameters: {},
        derivedKey: await pbkdf2Async(password, salt, parameters.cost, parameters.keyLength, getDigest(parameters.algorithm)),
    };
}
