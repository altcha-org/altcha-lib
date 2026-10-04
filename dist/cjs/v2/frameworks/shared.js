"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveHmacKeySecret = deriveHmacKeySecret;
exports.verify = verify;
const pow_js_1 = require("../pow.js");
const server_signature_js_1 = require("../server-signature.js");
const verify_server_js_1 = require("../verify-server.js");
const helpers_js_1 = require("../helpers.js");
const types_js_1 = require("../types.js");
async function deriveHmacKeySecret(masterSecret) {
    return (0, helpers_js_1.bufferToHex)(await (0, helpers_js_1.hmac)(types_js_1.HmacAlgorithm.SHA_256, masterSecret, 'derived-secret'));
}
async function verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store, verifyServerOptions) {
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
    try {
        switch (type) {
            case 'client':
                if (!deriveKey) {
                    throw new Error('deriveKey is required to verify self-hosted ALTCHA challenges.');
                }
                if (!hmacSignatureSecret) {
                    throw new Error('hmacSignatureSecret is required to verify self-hosted ALTCHA challenges.');
                }
                verification = await verifyClientPayload(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret);
                // Record the id only after verification, so unverified payloads cannot write to the store.
                if (store && verification.verified) {
                    await checkChallengeId(store, getChallengeId(payload));
                }
                break;
            case 'server': {
                const serverPayload = payload;
                if (verifyServerOptions) {
                    verification = await (0, verify_server_js_1.verifyServer)({
                        ...verifyServerOptions,
                        payload: serverPayload,
                    });
                }
                else {
                    if (!hmacSignatureSecret) {
                        throw new Error('hmacSignatureSecret or verifyServer must be configured to verify this payload.');
                    }
                    verification = await verifyServerSignaturePayload(serverPayload, hmacSignatureSecret);
                }
                // The top-level `id` is not covered by the signature; only trust the `id`
                // inside `verificationData`, and only once the signature has been verified.
                if (store && verification.verified) {
                    const signedId = new URLSearchParams(serverPayload.verificationData).get('id');
                    if (!signedId) {
                        throw new Error('ALTCHA payload is missing a signed id.');
                    }
                    await checkChallengeId(store, signedId);
                }
                break;
            }
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
            error: (verification && 'reason' in verification && verification.reason) ||
                'ALTCHA verification failed.',
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
/** Marks `challengeId` as used, or throws if it already was. */
async function checkChallengeId(store, challengeId) {
    if (store.setIfAbsent) {
        if (!(await store.setIfAbsent(challengeId, true))) {
            throw new Error('ALTCHA payload has been already used.');
        }
        return;
    }
    // Not atomic: concurrent submissions of the same payload can both pass.
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
