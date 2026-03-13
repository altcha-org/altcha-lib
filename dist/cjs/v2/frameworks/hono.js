"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.create = create;
const cookie_1 = require("hono/cookie");
const http_exception_1 = require("hono/http-exception");
const pow_js_1 = require("../pow.js");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    const challengeHandler = async (c) => {
        return c.json({
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
        });
    };
    const verifyHandler = async (c) => {
        return c.json(await (0, shared_js_1.verify)(await getPayloadFromContext(c), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store));
    };
    const getPayloadFromContext = async (c, cookieName) => {
        let payload = undefined;
        if (cookieName) {
            payload = (0, cookie_1.getCookie)(c, cookieName);
        }
        else {
            const contentType = c.req.header('content-type') ?? '';
            let body = null;
            if (contentType.includes('application/json')) {
                body = await c.req.json();
            }
            else if (contentType.includes('multipart/form-data') ||
                contentType.includes('application/x-www-form-urlencoded')) {
                body = await c.req.parseBody();
            }
            payload = body?.[fieldName];
        }
        return payload;
    };
    const middleware = (options = {}) => {
        const { throwOnFailure = true } = options;
        return async (c, next) => {
            const { error, payload, verification } = await (0, shared_js_1.verify)(await getPayloadFromContext(c, setCookie?.name), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
            c.set('altcha', {
                error,
                payload,
                verification,
            });
            if (setCookie) {
                (0, cookie_1.deleteCookie)(c, setCookie.name);
            }
            if (error && throwOnFailure) {
                throw new http_exception_1.HTTPException(403, {
                    message: error,
                });
            }
            return next();
        };
    };
    return {
        challengeHandler,
        verifyHandler,
        getPayloadFromContext,
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
