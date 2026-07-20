"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.create = create;
const pow_js_1 = require("../pow.js");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
const asyncHandler = (fn) => (req, res, next) => {
    fn(req, res, next).catch(next);
};
function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, verifyServer: verifyServerOptions, } = options;
    const challengeHandler = asyncHandler(async (req, res) => {
        if (!deriveKey || !createChallengeParameters) {
            throw new Error('deriveKey and createChallengeParameters are required to generate challenges. Omit challengeHandler when relying on Sentinel to issue challenges.');
        }
        const challenge = await (0, pow_js_1.createChallenge)({
            deriveKey,
            hmacSignatureSecret,
            hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        res.set('Cache-Control', 'no-store').json({
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...challenge,
        });
    });
    const verifyHandler = asyncHandler(async (req, res) => {
        const payload = await getPayloadFromRequest(req);
        const result = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store, verifyServerOptions);
        res.json(result);
    });
    const getPayloadFromRequest = async (req, cookieName) => {
        if (cookieName) {
            return req.cookies?.[cookieName];
        }
        return req.body?.[fieldName];
    };
    const middleware = (options = {}) => {
        const { throwOnFailure = true } = options;
        return asyncHandler(async (req, res, next) => {
            const payload = await getPayloadFromRequest(req, setCookie?.name);
            const { error, payload: resultPayload, verification, } = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store, verifyServerOptions);
            res.locals.altcha = {
                error,
                payload: resultPayload,
                verification,
            };
            if (setCookie) {
                res.clearCookie(setCookie.name);
            }
            if (error && throwOnFailure) {
                throw Object.assign(new Error(error), { status: 403 });
            }
            next();
        });
    };
    return {
        challengeHandler,
        verifyHandler,
        getPayloadFromRequest,
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
