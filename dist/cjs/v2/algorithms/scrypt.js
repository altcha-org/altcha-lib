"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const node_crypto_1 = require("node:crypto");
const node_util_1 = require("node:util");
const scryptAsync = (0, node_util_1.promisify)(node_crypto_1.scrypt);
async function deriveKey(parameters, salt, password) {
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
