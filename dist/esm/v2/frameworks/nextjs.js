import { randomInt } from '../helpers.js';
import { createChallenge } from '../pow.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
function getCookieFromRequest(req, name) {
    const header = req.headers.get('cookie');
    if (!header) {
        return undefined;
    }
    const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : undefined;
}
function deleteCookie(res, name, path) {
    res.headers.append('Set-Cookie', `${name}=; Path=${path ?? '/'}; Max-Age=0`);
}
export function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async function challengeHandler(_req) {
        const challenge = await createChallenge({
            deriveKey,
            hmacSignatureSecret,
            hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        const body = {
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...challenge,
        };
        const response = Response.json(body, {
            headers: { 'Cache-Control': 'no-store' },
        });
        return response;
    }
    async function verifyHandler(req) {
        const payload = await getPayloadFromRequest(req);
        const result = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        return Response.json(result);
    }
    async function getPayloadFromRequest(req, cookieName) {
        let payload = undefined;
        if (cookieName) {
            payload = getCookieFromRequest(req, cookieName);
        }
        else {
            const contentType = req.headers.get('content-type') ?? '';
            let body = null;
            if (contentType.includes('application/json')) {
                body = await req.json();
            }
            else if (contentType.includes('multipart/form-data') ||
                contentType.includes('application/x-www-form-urlencoded')) {
                body = Object.fromEntries((await req.formData()).entries());
            }
            payload = body?.[fieldName];
        }
        return payload;
    }
    async function middleware(req, throwOnFailure = true) {
        const payload = await getPayloadFromRequest(req, setCookie?.name);
        const { error, payload: verifiedPayload, verification, } = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        const result = {
            error,
            payload: verifiedPayload,
            verification,
        };
        const response = Response.json(result);
        if (setCookie) {
            deleteCookie(response, setCookie.name, setCookie.path);
        }
        if (error && throwOnFailure) {
            return Response.json({ error }, { status: 403 });
        }
        return response;
    }
    function withMiddleware(handler, options = {}) {
        const { throwOnFailure = true } = options;
        return async (req) => {
            const result = await middleware(req, throwOnFailure);
            // If middleware returned a Response, it means verification failed
            if (result instanceof Response) {
                return result;
            }
            // Attach the result to the request for the handler to access
            req.__altcha = result;
            return handler(req);
        };
    }
    return {
        challengeHandler,
        withMiddleware,
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
