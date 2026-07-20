"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.create = create;
const h3_1 = require("h3");
const pow_js_1 = require("../pow.js");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, verifyServer: verifyServerOptions, } = options;
    const challengeHandler = (0, h3_1.defineEventHandler)(async (event) => {
        if (!deriveKey || !createChallengeParameters) {
            throw new h3_1.HTTPError({
                message: 'deriveKey and createChallengeParameters are required to generate challenges. Omit challengeHandler when relying on Sentinel to issue challenges.',
                status: 500,
            });
        }
        (0, h3_1.setResponseHeader)(event, 'Cache-Control', 'no-store');
        return {
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...(await (0, pow_js_1.createChallenge)({
                deriveKey,
                hmacSignatureSecret,
                hmacKeySignatureSecret,
                ...createChallengeParameters(),
            })),
        };
    });
    const verifyHandler = (0, h3_1.defineEventHandler)(async (event) => {
        return await (0, shared_js_1.verify)(await getPayloadFromEvent(event), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
    });
    const getPayloadFromEvent = async (event, cookieName) => {
        let payload = undefined;
        if (cookieName) {
            payload = (0, h3_1.getCookie)(event, cookieName);
        }
        else {
            const contentType = event.req.headers.get('content-type') ?? '';
            let body = null;
            if (contentType.includes('application/json')) {
                body = await (0, h3_1.readBody)(event);
            }
            else if (contentType.includes('multipart/form-data')) {
                const formData = await event.req.formData();
                const value = formData.get(fieldName);
                if (typeof value === 'string') {
                    payload = value;
                }
                return payload;
            }
            else if (contentType.includes('application/x-www-form-urlencoded')) {
                body = await (0, h3_1.readBody)(event);
            }
            payload = body?.[fieldName];
        }
        return payload;
    };
    const middleware = (options = {}) => {
        const { throwOnFailure = true } = options;
        return (0, h3_1.defineEventHandler)(async (event) => {
            const { error, payload, verification } = await (0, shared_js_1.verify)(await getPayloadFromEvent(event, setCookie?.name), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store, verifyServerOptions);
            event.context.altcha = {
                error,
                payload,
                verification,
            };
            if (setCookie) {
                (0, h3_1.deleteCookie)(event, setCookie.name);
            }
            if (error && throwOnFailure) {
                throw new h3_1.HTTPError({ message: error, status: 403 });
            }
        });
    };
    return {
        challengeHandler,
        verifyHandler,
        getPayloadFromEvent,
        middleware,
        verify: shared_js_1.verify,
    };
}
exports.default = {
    CappedMap: capped_map_js_1.CappedMap,
    create,
    deriveHmacKeySecret: shared_js_1.deriveHmacKeySecret,
    randomInt: helpers_js_1.randomInt,
};
