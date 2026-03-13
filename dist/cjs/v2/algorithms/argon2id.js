"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const node_crypto_1 = __importDefault(require("node:crypto"));
const node_util_1 = require("node:util");
const argon2Async = 'argon2' in node_crypto_1.default
    ? (0, node_util_1.promisify)(node_crypto_1.default.argon2)
    : async () => {
        throw new Error('Argon2 not supported in node:crypto.');
    };
async function deriveKey(parameters, salt, password) {
    return {
        parameters: {},
        derivedKey: await argon2Async('argon2id', {
            memory: parameters.memoryCost,
            parallelism: parameters.parallelism || 1,
            nonce: salt,
            message: password,
            passes: parameters.cost,
            tagLength: parameters.keyLength,
        }),
    };
}
