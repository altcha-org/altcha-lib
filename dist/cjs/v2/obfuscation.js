"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deobfuscate = deobfuscate;
exports.obfuscate = obfuscate;
const pbkdf2_js_1 = require("./algorithms/pbkdf2.js");
const pow_js_1 = require("./pow.js");
const helpers_js_1 = require("./helpers.js");
async function deobfuscate(obfuscatedData, options = {}) {
    const { concurrency = navigator.hardwareConcurrency, createWorker, deriveKey = pbkdf2_js_1.deriveKey, } = options;
    let challenge = null;
    try {
        challenge = JSON.parse(atob(obfuscatedData));
    }
    catch {
        throw new Error(`Unable to parse obfuscated data.`);
    }
    if (!challenge ||
        typeof challenge !== 'object' ||
        !('parameters' in challenge) ||
        !('cipher' in challenge)) {
        throw new Error(`Invalid obfuscated data format.`);
    }
    const cipher = challenge.cipher;
    let solution = null;
    if (createWorker) {
        solution = await (0, pow_js_1.solveChallengeWorkers)({
            challenge,
            concurrency,
            createWorker,
        });
    }
    else {
        solution = await (0, pow_js_1.solveChallenge)({
            challenge,
            deriveKey,
        });
    }
    if (!solution) {
        throw new Error('Unable to find solution.');
    }
    const key = await crypto.subtle.importKey('raw', (0, helpers_js_1.hexToBuffer)(solution.derivedKey), { name: 'AES-GCM' }, false, ['decrypt']);
    const result = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: (0, helpers_js_1.hexToBuffer)(cipher.iv),
    }, key, (0, helpers_js_1.hexToBuffer)(cipher.data));
    return new TextDecoder().decode(result);
}
async function obfuscate(str, options = {}) {
    const { deriveKey = pbkdf2_js_1.deriveKey } = options;
    const counterMin = options?.counterMin || 20;
    const counterMax = options?.counterMax || 200;
    const { parameters } = await (0, pow_js_1.createChallenge)({
        algorithm: 'PBKDF2/SHA-256',
        cost: 5000,
        deriveKey,
        counter: Math.floor(Math.random() * (counterMax - counterMin + 1)) + counterMin,
        keyPrefixLength: 32,
        ...options,
    });
    const key = await crypto.subtle.importKey('raw', (0, helpers_js_1.hexToBuffer)(parameters.keyPrefix), { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(str));
    return btoa(JSON.stringify({
        parameters: {
            ...parameters,
            // Return only half the derived key
            keyPrefix: parameters.keyPrefix.slice(0, parameters.keyLength || 32),
        },
        cipher: {
            iv: (0, helpers_js_1.bufferToHex)(iv),
            data: (0, helpers_js_1.bufferToHex)(data),
        },
    }));
}
