"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.randomBytes = exports.hmacHex = exports.hmac = exports.hashHex = exports.hash = exports.ab2hex = exports.encoder = void 0;
// @denoify-line-ignore
require("./crypto.js");
exports.encoder = new TextEncoder();
function ab2hex(ab) {
    return [...new Uint8Array(ab)]
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');
}
exports.ab2hex = ab2hex;
async function hash(algorithm, data) {
    return crypto.subtle.digest(algorithm.toUpperCase(), typeof data === 'string' ? exports.encoder.encode(data) : new Uint8Array(data));
}
exports.hash = hash;
async function hashHex(algorithm, data) {
    return ab2hex(await hash(algorithm, data));
}
exports.hashHex = hashHex;
async function hmac(algorithm, data, secret) {
    const key = await crypto.subtle.importKey('raw', exports.encoder.encode(secret), {
        name: 'HMAC',
        hash: algorithm,
    }, false, ['sign', 'verify']);
    return crypto.subtle.sign('HMAC', key, typeof data === 'string' ? exports.encoder.encode(data) : new Uint8Array(data));
}
exports.hmac = hmac;
async function hmacHex(algorithm, data, secret) {
    return ab2hex(await hmac(algorithm, data, secret));
}
exports.hmacHex = hmacHex;
function randomBytes(length) {
    const ab = new Uint8Array(length);
    crypto.getRandomValues(ab);
    return ab;
}
exports.randomBytes = randomBytes;
function randomInt(max) {
    const ab = new Uint32Array(1);
    crypto.getRandomValues(ab);
    const randomNumber = ab[0] / (0xffffffff + 1);
    return Math.floor(randomNumber * max + 1);
}
exports.randomInt = randomInt;
