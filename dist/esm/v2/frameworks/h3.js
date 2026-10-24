import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
/**
 * h3 v1 caches the raw request body under this global symbol (`readRawBody`), so the
 * app's own `readBody` can still read a body that the middleware already consumed.
 */
const kH3RawBody = Symbol.for('h3RawBody');
/**
 * Thrown error recognized by both h3 majors: v1 checks the static `__h3_error__` marker,
 * v2 checks `name === 'HTTPError'` and `status`. Errors failing these checks are reported
 * as unhandled 500s.
 */
class AltchaHTTPError extends Error {
    static __h3_error__ = true;
    status;
    statusCode;
    fatal = false;
    unhandled = false;
    constructor(status, message) {
        super(message);
        this.name = 'HTTPError';
        this.status = status;
        this.statusCode = status;
    }
    toJSON() {
        return {
            message: this.message,
            status: this.status,
            statusCode: this.statusCode,
        };
    }
}
/** Reads `key` from `value` if it is an object, including inherited getters. */
function readProperty(value, key) {
    return typeof value === 'object' && value !== null
        ? Reflect.get(value, key)
        : undefined;
}
/** Reads an own property of a parsed body, ignoring inherited keys such as `constructor`. */
function readOwnProperty(value, key) {
    return typeof value === 'object' &&
        value !== null &&
        Object.prototype.hasOwnProperty.call(value, key)
        ? Reflect.get(value, key)
        : undefined;
}
function isWebEvent(event) {
    // h3 v1 events also expose `req` (deprecated alias of `node.req`), with plain-object headers.
    const headers = readProperty(readProperty(event, 'req'), 'headers');
    return typeof readProperty(headers, 'get') === 'function';
}
function getRequestHeader(event, name) {
    if (isWebEvent(event)) {
        return event.req.headers.get(name) ?? undefined;
    }
    const value = event.node.req.headers[name];
    return Array.isArray(value) ? value.join(', ') : value;
}
function setResponseHeader(event, name, value) {
    if (isWebEvent(event)) {
        event.res.headers.set(name, value);
    }
    else {
        event.node.res.setHeader(name, value);
    }
}
function appendResponseHeader(event, name, value) {
    if (isWebEvent(event)) {
        event.res.headers.append(name, value);
        return;
    }
    const res = event.node.res;
    const current = res.getHeader(name);
    if (current === undefined) {
        res.setHeader(name, value);
    }
    else {
        res.setHeader(name, [
            ...(Array.isArray(current) ? current : [String(current)]),
            value,
        ]);
    }
}
function getCookie(event, name) {
    const header = getRequestHeader(event, 'cookie');
    if (!header) {
        return undefined;
    }
    for (const part of header.split(';')) {
        const index = part.indexOf('=');
        if (index === -1 || part.slice(0, index).trim() !== name) {
            continue;
        }
        let value = part.slice(index + 1).trim();
        if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
            value = value.slice(1, -1);
        }
        try {
            return decodeURIComponent(value);
        }
        catch {
            return value;
        }
    }
    return undefined;
}
function deleteCookie(event, name) {
    appendResponseHeader(event, 'set-cookie', `${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
}
/**
 * Resolves the h3 v1 request body the way h3 v1's `readRawBody` does, and caches a
 * freshly read Node.js stream under `Symbol.for('h3RawBody')` so it stays readable.
 */
function readNodeRawBody(event) {
    const req = event.node.req;
    const source = readProperty(event, '_requestBody') ||
        readProperty(readProperty(readProperty(event, 'web'), 'request'), 'body') ||
        readProperty(req, kH3RawBody) ||
        readProperty(req, 'rawBody') ||
        readProperty(req, 'body');
    if (source) {
        return Promise.resolve(source);
    }
    if (!Number.parseInt(req.headers['content-length'] || '') &&
        !/\bchunked\b/i.test(String(req.headers['transfer-encoding'] ?? ''))) {
        return Promise.resolve(undefined);
    }
    const promise = readNodeStream(req);
    Reflect.set(req, kH3RawBody, promise);
    return promise;
}
async function readNodeStream(stream) {
    const chunks = [];
    let length = 0;
    for await (const chunk of stream) {
        const bytes = typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk;
        chunks.push(bytes);
        length += bytes.byteLength;
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result;
}
/** Wraps a resolved h3 v1 body source so it can be parsed like a web request body. */
async function toBodyReader(source, contentType) {
    if (source instanceof FormData || source instanceof URLSearchParams) {
        // Response derives a matching content-type (and multipart boundary) itself.
        return new Response(source);
    }
    let body;
    if (typeof source === 'string' || source instanceof Uint8Array) {
        body = source;
    }
    else if (source instanceof ReadableStream) {
        body = source;
    }
    else if (source !== null &&
        typeof source === 'object' &&
        Symbol.asyncIterator in source) {
        body = (await readNodeStream(source));
    }
    else {
        body = String(source);
    }
    return new Response(body, { headers: { 'content-type': contentType } });
}
async function readBodyField(event, contentType, fieldName) {
    const isJson = contentType.includes('application/json');
    const isMultipart = contentType.includes('multipart/form-data');
    const isUrlEncoded = contentType.includes('application/x-www-form-urlencoded');
    if (!isJson && !isMultipart && !isUrlEncoded) {
        return undefined;
    }
    let reader;
    if (isWebEvent(event)) {
        // Read a clone so handlers after the middleware can still read the body.
        reader = event.req.clone();
    }
    else {
        if (!['DELETE', 'PATCH', 'POST', 'PUT'].includes(event.node.req.method)) {
            return undefined;
        }
        const source = await readNodeRawBody(event);
        if (source === undefined || source === null) {
            return undefined;
        }
        if (Object.getPrototypeOf(source) === Object.prototype) {
            // Body already parsed into a plain object by an upstream body parser.
            return readOwnProperty(source, fieldName);
        }
        reader = await toBodyReader(source, contentType);
    }
    if (isMultipart) {
        let formData;
        try {
            formData = await reader.formData();
        }
        catch {
            throw new AltchaHTTPError(400, 'Invalid form data body');
        }
        return formData.get(fieldName);
    }
    const text = await reader.text();
    if (!text) {
        return undefined;
    }
    if (isUrlEncoded) {
        return new URLSearchParams(text).get(fieldName);
    }
    let body;
    try {
        body = JSON.parse(text);
    }
    catch {
        throw new AltchaHTTPError(400, 'Invalid JSON body');
    }
    return readOwnProperty(body, fieldName);
}
export function create(options) {
    const { createChallengeParameters, deriveKey, fieldName = 'altcha', hmacSignatureSecret, hmacKeySignatureSecret, setCookie, store, verifyServer: verifyServerOptions, } = options;
    const challengeHandler = async (event) => {
        if (!deriveKey || !createChallengeParameters || !hmacSignatureSecret) {
            throw new AltchaHTTPError(500, 'deriveKey, createChallengeParameters and hmacSignatureSecret are required to generate challenges. Omit challengeHandler when relying on Sentinel to issue challenges.');
        }
        setResponseHeader(event, 'cache-control', 'no-store');
        return {
            configuration: setCookie
                ? {
                    setCookie,
                }
                : undefined,
            ...(await createChallenge({
                deriveKey,
                hmacSignatureSecret,
                hmacKeySignatureSecret,
                ...createChallengeParameters(),
            })),
        };
    };
    const verifyHandler = async (event) => {
        return await verify(await getPayloadFromEvent(event), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store);
    };
    const getPayloadFromEvent = async (event, cookieName) => {
        if (cookieName) {
            return getCookie(event, cookieName);
        }
        const payload = await readBodyField(event, getRequestHeader(event, 'content-type') ?? '', fieldName);
        return typeof payload === 'string' ? payload : undefined;
    };
    const middleware = (options = {}) => {
        const { throwOnFailure = true } = options;
        return async (event) => {
            const { error, payload, verification } = await verify(await getPayloadFromEvent(event, setCookie?.name), deriveKey, hmacSignatureSecret, hmacKeySignatureSecret, store, verifyServerOptions);
            const altcha = { error, payload, verification };
            Object.assign(event.context, { altcha });
            if (setCookie) {
                deleteCookie(event, setCookie.name);
            }
            if (error && throwOnFailure) {
                throw new AltchaHTTPError(403, error);
            }
        };
    };
    return {
        challengeHandler,
        verifyHandler,
        getPayloadFromEvent,
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
