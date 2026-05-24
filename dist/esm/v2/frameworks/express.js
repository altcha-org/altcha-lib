import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
const asyncHandler = (fn) => (req, res, next) => {
    fn(req, res, next).catch(next);
};
export function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    const challengeHandler = asyncHandler(async (req, res) => {
        const challenge = await createChallenge({
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
        const result = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
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
            const { error, payload: resultPayload, verification, } = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
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
        verify,
    };
}
export default {
    CappedMap,
    create,
    deriveHmacKeySecret,
    randomInt,
};
