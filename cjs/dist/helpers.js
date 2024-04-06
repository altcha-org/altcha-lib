"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.randomBytes = exports.hmac = exports.hash = exports.ab2hex = exports.encoder = void 0;
require("./crypto.js");
exports.encoder = new TextEncoder();
function ab2hex(ab) {
    return [...new Uint8Array(ab)]
        .map((x) => x.toString(16).padStart(2, '0'))
        .join('');
}
exports.ab2hex = ab2hex;
async function hash(algorithm, str) {
    return ab2hex(await crypto.subtle.digest(algorithm.toUpperCase(), exports.encoder.encode(str)));
}
exports.hash = hash;
async function hmac(algorithm, str, secret) {
    const key = await crypto.subtle.importKey('raw', exports.encoder.encode(secret), {
        name: 'HMAC',
        hash: algorithm,
    }, false, ['sign', 'verify']);
    return ab2hex(await crypto.subtle.sign('HMAC', key, exports.encoder.encode(str)));
}
exports.hmac = hmac;
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
