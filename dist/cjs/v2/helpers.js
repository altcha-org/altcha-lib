"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bufferStartsWith = bufferStartsWith;
exports.bufferToHex = bufferToHex;
exports.canonicalJSON = canonicalJSON;
exports.concatBuffers = concatBuffers;
exports.hexToBuffer = hexToBuffer;
exports.constantTimeEqual = constantTimeEqual;
exports.delay = delay;
exports.hash = hash;
exports.hmac = hmac;
exports.injectCss = injectCss;
exports.randomInt = randomInt;
exports.sortKeys = sortKeys;
exports.timeDuration = timeDuration;
/** Checks if a buffer starts with the given prefix bytes. */
function bufferStartsWith(buffer, prefix) {
    if (prefix.length > buffer.length) {
        return false;
    }
    for (let i = 0; i < prefix.length; i++) {
        if (buffer[i] !== prefix[i]) {
            return false;
        }
    }
    return true;
}
/** Converts a byte buffer to a lowercase hex string. */
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}
/** Returns a canonical (sorted-key) JSON string for consistent hashing/signing. */
function canonicalJSON(obj) {
    return JSON.stringify(sortKeys(obj));
}
/** Concatenates two Uint8Arrays into a new buffer. */
function concatBuffers(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}
/** Converts a hex string to a Uint8Array. Throws if the string has odd length. */
function hexToBuffer(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error(`Hex string must have an even length. Got: ${hex}`);
    }
    const buffer = new ArrayBuffer(hex.length / 2);
    const view = new DataView(buffer);
    for (let i = 0; i < hex.length; i += 2) {
        const byteString = hex.substring(i, i + 2);
        const byteValue = parseInt(byteString, 16);
        view.setUint8(i / 2, byteValue);
    }
    return new Uint8Array(buffer);
}
/** Checks if two strings are equal in constant time. */
function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}
/** Yields to the event loop after the given milliseconds. */
async function delay(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
}
/** Generate a SHA hash */
async function hash(algorithm, data) {
    return new Uint8Array(await crypto.subtle.digest(algorithm.toUpperCase(), typeof data === 'string'
        ? new TextEncoder().encode(data)
        : new Uint8Array(data)));
}
/** Computes an HMAC signature using the Web Crypto API. */
async function hmac(algorithm, data, keyStr) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(keyStr), {
        name: 'HMAC',
        hash: { name: algorithm },
    }, false, ['sign', 'verify']);
    const signature = await crypto.subtle.sign('HMAC', key, typeof data === 'string'
        ? new TextEncoder().encode(data)
        : data);
    return new Uint8Array(signature);
}
/** Inject CSS tag into the document */
function injectCss(css, id = 'altcha-css') {
    if (typeof document !== 'undefined' &&
        document &&
        !document.getElementById(id)) {
        const style = document.createElement('style');
        style.id = id;
        style.textContent = css;
        document.head.appendChild(style);
    }
}
/** Generates a random integer between the specified minimum and maximum values (inclusive). */
function randomInt(max, min = 1) {
    const ab = new Uint32Array(1);
    crypto.getRandomValues(ab);
    const randomNumber = ab[0] / (0xffffffff + 1);
    return Math.floor(randomNumber * (max - min + 1) + min);
}
/** Recursively sorts object keys alphabetically for deterministic serialization. */
function sortKeys(obj) {
    if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
        return obj;
    }
    return Object.keys(obj)
        .sort()
        .reduce((acc, key) => {
        const value = obj[key];
        if (value !== undefined) {
            acc[key] = sortKeys(value);
        }
        return acc;
    }, {});
}
/** Returns elapsed time in milliseconds since `start`, rounded to one decimal. */
function timeDuration(start) {
    return Math.floor((performance.now() - start) * 10) / 10;
}
