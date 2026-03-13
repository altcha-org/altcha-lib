"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveHmacKeySecret = deriveHmacKeySecret;
exports.verify = verify;
const pow_js_1 = require("../pow.js");
const server_signature_js_1 = require("../server-signature.js");
const helpers_js_1 = require("../helpers.js");
const types_js_1 = require("../types.js");
async function deriveHmacKeySecret(masterSecret) {
    return (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(types_js_1.HmacAlgorithm.SHA_256, masterSecret, 'derived-secret'));
}
async function verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store) {
    if (!payload) {
        return {
            error: 'ALTCHA payload is missing.',
            payload: null,
            verification: null,
        };
    }
    if (typeof payload === 'string') {
        payload = parsePayload(payload);
    }
    if (!payload) {
        return {
            error: 'ALTCHA payload is invalid.',
            payload: null,
            verification: null,
        };
    }
    const type = getPayloadType(payload);
    let verification = null;
    let challengeId = null;
    try {
        switch (type) {
            case 'client':
                challengeId = getChallengeId(payload);
                if (store && challengeId) {
                    await checkChallengeId(store, challengeId);
                }
                verification = await verifyClientPayload(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret);
                break;
            case 'server':
                challengeId = payload.id;
                if (store && challengeId) {
                    await checkChallengeId(store, challengeId);
                }
                verification = await verifyServerSignaturePayload(payload, hmacSignatureSecret);
                break;
            default:
                throw new Error('ALTCHA payload is invalid.');
        }
    }
    catch (err) {
        return {
            error: err instanceof Error ? err.message : 'Unknown error',
            payload: payload,
            verification: null,
        };
    }
    if (!verification?.verified) {
        return {
            error: 'ALTCHA verification failed.',
            payload: payload,
            verification,
        };
    }
    return {
        error: null,
        payload: payload,
        verification,
    };
}
async function checkChallengeId(store, challengeId) {
    if (await store.get(challengeId)) {
        throw new Error('ALTCHA payload has been already used.');
    }
    await store.set(challengeId, true);
}
function getChallengeId(payload) {
    const { challenge } = payload;
    const data = challenge.parameters.data;
    return data?.challengeId
        ? String(data.challengeId)
        : challenge.parameters.nonce;
}
function getPayloadType(payload) {
    if (!payload || typeof payload !== 'object') {
        return null;
    }
    if ('verificationData' in payload) {
        return 'server';
    }
    if ('challenge' in payload && 'solution' in payload) {
        return 'client';
    }
    return null;
}
function parsePayload(payload) {
    try {
        return JSON.parse(atob(payload));
    }
    catch {
        return null;
    }
}
function verifyClientPayload(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret) {
    const { challenge, solution } = payload;
    return (0, pow_js_1.verifySolution)({
        challenge,
        deriveKey,
        hmacSignatureSecret,
        hmacKeySignatureSecret,
        solution,
    });
}
async function verifyServerSignaturePayload(payload, hmacSecret) {
    return (0, server_signature_js_1.verifyServerSignature)({
        payload,
        hmacSecret,
    });
}
