import { error, json } from '@sveltejs/kit';
import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
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
export function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, } = options;
    async function challengeHandler() {
        const challenge = await createChallenge({
            deriveKey,
            hmacSignatureSecret,
            hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        return json({
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...challenge,
        }, { headers: { 'Cache-Control': 'no-store' } });
    }
    async function verifyHandler(event) {
        const payload = await getPayloadFromEvent(event, fieldName);
        const result = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
        return json(result);
    }
    function createHandle(middlewareOptions = {}) {
        const { throwOnFailure = true } = middlewareOptions;
        return async ({ event, resolve }) => {
            const payload = await getPayloadFromEvent(event, fieldName, setCookie?.name);
            const { error: verifyError, payload: resultPayload, verification, } = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
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
                error(403, verifyError);
            }
            return resolve(event);
        };
    }
    async function verifyEvent(event) {
        const payload = await getPayloadFromEvent(event, fieldName, setCookie?.name);
        const { error: verifyError, payload: resultPayload, verification, } = await verify(payload, deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
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
        verify,
    };
}
export default {
    CappedMap,
    create,
    deriveHmacKeySecret,
    randomInt,
};
