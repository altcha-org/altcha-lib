"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveKey = deriveKey;
const helpers_js_1 = require("../../helpers.js");
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
        derivedKey = new Uint8Array((await crypto.subtle.digest(algorithm, data)).slice(0, keyLength));
    }
    return {
        parameters: {},
        derivedKey: derivedKey,
    };
}
