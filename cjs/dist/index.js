"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifySolution = exports.createChallenge = void 0;
const helpers_js_1 = require("./helpers.js");
const DEFAULT_MAX_NUMBER = 1e6;
const DEFAULT_SALT_LEN = 12;
const DEFAULT_ALG = 'SHA-256';
async function createChallenge(options) {
    const algorithm = options.algorithm || DEFAULT_ALG;
    const maxNumber = options.maxNumber || DEFAULT_MAX_NUMBER;
    const saltLength = options.saltLength || DEFAULT_SALT_LEN;
    const salt = options.salt || (0, helpers_js_1.ab2hex)((0, helpers_js_1.randomBytes)(saltLength));
    const number = options.number === void 0 ? (0, helpers_js_1.randomInt)(maxNumber) : options.number;
    const challenge = await (0, helpers_js_1.hash)(algorithm, salt + number);
    return {
        algorithm,
        challenge,
        salt,
        signature: await (0, helpers_js_1.hmac)(algorithm, challenge, options.hmacKey),
    };
}
exports.createChallenge = createChallenge;
async function verifySolution(payload, hmacKey) {
    if (typeof payload === 'string') {
        payload = JSON.parse(atob(payload));
    }
    const check = await createChallenge({
        algorithm: payload.algorithm,
        hmacKey,
        number: payload.number,
        salt: payload.salt,
    });
    return (check.challenge === payload.challenge &&
        check.signature === payload.signature);
}
exports.verifySolution = verifySolution;
