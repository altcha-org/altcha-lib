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
function create(options) {
    const { createChallengeParameters, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    const deleteCookie = (reply, name, path = '/') => {
        reply.header('Set-Cookie', `${name}=; Path=${path ?? '/'}; Max-Age=0`);
    };
    const parseCookies = (request) => {
        if ('cookies' in request) {
            return request.cookies;
        }
        const header = request.headers.cookie;
        if (!header) {
            return {};
        }
        return Object.fromEntries(header.split(';').map((pair) => {
            const [key, ...rest] = pair.trim().split('=');
            return [key, decodeURIComponent(rest.join('='))];
        }));
    };
    const getPayloadFromRequest = async (request, cookieName) => {
        if (cookieName) {
            return parseCookies(request)[cookieName];
        }
        return request.body?.altcha;
    };
    const challengeHandler = async (request, reply) => {
        const challenge = await (0, pow_js_1.createChallenge)({
            deriveKey,
            hmacSignatureSecret,
            hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        return reply.send({
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...challenge,
        });
    };
    const verifyHandler = async (request, reply) => {
        const payload = await getPayloadFromRequest(request);
        const result = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        return reply.send(result);
    };
    const middleware = (options = {}) => {
        const { throwOnFailure = true } = options;
        return async (request, reply) => {
            const payload = await getPayloadFromRequest(request, setCookie?.name);
            const { error, payload: resultPayload, verification, } = await (0, shared_js_1.verify)(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
            request.altcha = {
                error,
                payload: resultPayload,
                verification,
            };
            if (setCookie) {
                deleteCookie(reply, setCookie.name, setCookie.path);
            }
            if (error && throwOnFailure) {
                return reply.code(403).send({ error });
            }
        };
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
