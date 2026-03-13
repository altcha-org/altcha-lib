"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.create = create;
const kit_1 = require("@sveltejs/kit");
const pow_js_1 = require("../pow.js");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
async function getPayloadFromEvent(event, fieldName, cookieName) {
    if (cookieName) {
        return event.cookies.get(cookieName);
    }
    const contentType = event.request.headers.get('content-type') ?? '';
    let body = null;
    if (contentType.includes('application/json')) {
        body = await event.request.json();
    }
    else if (contentType.includes('multipart/form-data') ||
        contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await event.request.formData();
        body = Object.fromEntries(formData.entries());
    }
    return body?.[fieldName];
}
function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    async function challengeHandler() {
        const challenge = await (0, pow_js_1.createChallenge)({
            deriveKey,
            hmacSignatureSecret,
            hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        return (0, kit_1.json)({
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...challenge,
        });
    }
    async function verifyHandler(event) {
        const payload = await getPayloadFromEvent(event, fieldName);
        const result = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        return (0, kit_1.json)(result);
    }
    function createHandle(middlewareOptions = {}) {
        const { throwOnFailure = true } = middlewareOptions;
        return async ({ event, resolve }) => {
            const payload = await getPayloadFromEvent(event, fieldName, setCookie?.name);
            const { error: verifyError, payload: resultPayload, verification, } = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
            event.locals.altcha = {
                error: verifyError,
                payload: resultPayload,
                verification,
            };
            if (setCookie) {
                event.cookies.delete(setCookie.name, {
                    path: setCookie.path ?? '/',
                });
            }
            if (verifyError && throwOnFailure) {
                (0, kit_1.error)(403, verifyError);
            }
            return resolve(event);
        };
    }
    async function verifyEvent(event) {
        const payload = await getPayloadFromEvent(event, fieldName, setCookie?.name);
        const { error: verifyError, payload: resultPayload, verification, } = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        if (setCookie) {
            event.cookies.delete(setCookie.name, {
                path: setCookie.path ?? '/',
            });
        }
        return {
            error: verifyError,
            payload: resultPayload,
            verification,
        };
    }
    return {
        challengeHandler,
        verifyHandler,
        verifyEvent,
        createHandle,
        getPayloadFromEvent: (event, cookieName) => getPayloadFromEvent(event, fieldName, cookieName),
        verify: shared_js_1.verify,
    };
}
exports.default = {
    CappedMap: capped_map_js_1.CappedMap,
    create,
    deriveHmacKeySecret: shared_js_1.deriveHmacKeySecret,
    randomInt: helpers_js_1.randomInt,
};
