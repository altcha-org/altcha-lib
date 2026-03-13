"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const node_crypto_1 = require("node:crypto");
const node_util_1 = require("node:util");
const pbkdf2Async = (0, node_util_1.promisify)(node_crypto_1.pbkdf2);
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
async function deriveKey(parameters, salt, password) {
    return {
        parameters: {},
        derivedKey: await pbkdf2Async(password, salt, parameters.cost, parameters.keyLength, getDigest(parameters.algorithm)),
    };
}
