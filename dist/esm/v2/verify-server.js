import { delay } from './helpers.js';
/** Verifies a payload remotely via the ALTCHA Sentinel `/v2/verify/signature` API. */
export async function verifyServer(options) {
    const { apiKey, controller, fetch: fetchImpl = fetch, headers, payload, retries = 0, retryBackoff = 'exponential', retryDelay = 300, secret, timeout = 10_000, url, } = options;
    // `secret` is only understood by a v1 Sentinel; Sentinel v2 rejects it next to credentials.
    const body = JSON.stringify(apiKey || secret === undefined ? { payload } : { payload, secret });
    const authHeaders = apiKey
        ? { Authorization: basicAuthorization(apiKey) }
        : {};
    for (let attempt = 0; attempt <= retries; attempt++) {
        if (controller?.signal.aborted) {
            return { verified: false, reason: 'ABORTED' };
        }
        const attemptController = new AbortController();
        const onAbort = () => attemptController.abort();
        controller?.signal.addEventListener('abort', onAbort);
        const timer = setTimeout(() => attemptController.abort(), timeout);
        try {
            const response = await fetchImpl(url, {
                body,
                headers: {
                    'Content-Type': 'application/json',
                    ...authHeaders,
                    ...headers,
                },
                method: 'POST',
                signal: attemptController.signal,
            });
            if (!response.ok) {
                const reason = await errorReason(response);
                // A 4xx (bad payload, bad credentials, wrong account) fails the same way again.
                if (response.status >= 400 && response.status < 500) {
                    return { verified: false, reason };
                }
                throw new Error(reason);
            }
            const result = (await response.json());
            return {
                ...result,
                verificationData: isPlainObject(result.verificationData)
                    ? flattenVerificationData(result.verificationData)
                    : result.verificationData,
            };
        }
        catch (err) {
            if (attempt >= retries) {
                return {
                    verified: false,
                    reason: err instanceof Error ? err.message : 'NETWORK_ERROR',
                };
            }
            const backoffDelay = retryBackoff === 'fixed' ? retryDelay : retryDelay * 2 ** attempt;
            await delay(backoffDelay);
        }
        finally {
            clearTimeout(timer);
            controller?.signal.removeEventListener('abort', onAbort);
        }
    }
    return { verified: false, reason: 'NETWORK_ERROR' };
}
/** `Basic base64(id:secret)`, UTF-8 encoded. */
function basicAuthorization(apiKey) {
    const bytes = new TextEncoder().encode(`${apiKey.id}:${apiKey.secret}`);
    return `Basic ${btoa(String.fromCharCode(...bytes))}`;
}
/**
 * The `code` of a Sentinel error body (`{ code, error, statusCode }`), else its `error`
 * (a v1 Sentinel sends only `error`), else `HTTP_<status>`.
 */
async function errorReason(response) {
    const data = await response.json().catch(() => null);
    if (isPlainObject(data)) {
        if (typeof data.code === 'string' && data.code) {
            return data.code;
        }
        if (typeof data.error === 'string' && data.error) {
            return data.error;
        }
    }
    return `HTTP_${response.status}`;
}
/**
 * Sentinel v2 nests `verificationData` on dots (`{ device: { browser } }`); flattens it
 * back to the signed keys (`'device.browser'`) that `verifyServerSignature` returns.
 * Already-flat data (a v1 Sentinel) is returned unchanged.
 */
function flattenVerificationData(data) {
    const entries = [];
    const walk = (obj, prefix) => {
        for (const [key, value] of Object.entries(obj)) {
            const path = prefix ? `${prefix}.${key}` : key;
            if (isPlainObject(value)) {
                walk(value, path);
            }
            else {
                entries.push([path, value]);
            }
        }
    };
    walk(data, '');
    // `Object.fromEntries` keeps a `__proto__` key an own property.
    return Object.fromEntries(entries);
}
function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value);
}
