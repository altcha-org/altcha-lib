import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
// Type-only: resolves the `h3` module for the `H3EventContext` augmentation below.
import type {} from 'h3';

export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };

declare module 'h3' {
	interface H3EventContext {
		altcha?: AltchaResult;
	}
}

/*
 * This module supports h3 v1 (Nuxt 4, Nitro 2) and h3 v2 (Nitro 3). It must not import
 * h3 at runtime: package managers may resolve a different h3 major for altcha-lib than the
 * one that creates the events (e.g. pnpm installs h3 v2 next to Nuxt 4's h3 v1), and each
 * major's helpers only understand its own event shape.
 */

/** h3 v2 event: `req` is a web `Request`, `res.headers` the response headers. */
export interface H3WebEvent {
	req: Request;
	res: { headers: Headers };
	context: object;
}

/** h3 v1 event: Node.js `req`/`res` under `node`. */
export interface H3NodeEvent {
	node: { req: IncomingMessage; res: ServerResponse };
	context: object;
}

export type H3EventLike = H3WebEvent | H3NodeEvent;

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
	static readonly __h3_error__ = true;
	readonly status: number;
	readonly statusCode: number;
	readonly fatal = false;
	readonly unhandled = false;

	constructor(status: number, message: string) {
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
function readProperty(value: unknown, key: PropertyKey): unknown {
	return typeof value === 'object' && value !== null
		? Reflect.get(value, key)
		: undefined;
}

/** Reads an own property of a parsed body, ignoring inherited keys such as `constructor`. */
function readOwnProperty(value: unknown, key: string): unknown {
	return typeof value === 'object' &&
		value !== null &&
		Object.prototype.hasOwnProperty.call(value, key)
		? Reflect.get(value, key)
		: undefined;
}

function isWebEvent(event: H3EventLike): event is H3WebEvent {
	// h3 v1 events also expose `req` (deprecated alias of `node.req`), with plain-object headers.
	const headers = readProperty(readProperty(event, 'req'), 'headers');
	return typeof readProperty(headers, 'get') === 'function';
}

function getRequestHeader(event: H3EventLike, name: string) {
	if (isWebEvent(event)) {
		return event.req.headers.get(name) ?? undefined;
	}
	const value = event.node.req.headers[name];
	return Array.isArray(value) ? value.join(', ') : value;
}

function setResponseHeader(event: H3EventLike, name: string, value: string) {
	if (isWebEvent(event)) {
		event.res.headers.set(name, value);
	} else {
		event.node.res.setHeader(name, value);
	}
}

function appendResponseHeader(event: H3EventLike, name: string, value: string) {
	if (isWebEvent(event)) {
		event.res.headers.append(name, value);
		return;
	}
	const res = event.node.res;
	const current = res.getHeader(name);
	if (current === undefined) {
		res.setHeader(name, value);
	} else {
		res.setHeader(name, [
			...(Array.isArray(current) ? current : [String(current)]),
			value,
		]);
	}
}

function getCookie(event: H3EventLike, name: string) {
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
		} catch {
			return value;
		}
	}
	return undefined;
}

function deleteCookie(event: H3EventLike, name: string) {
	appendResponseHeader(
		event,
		'set-cookie',
		`${name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
	);
}

/**
 * Resolves the h3 v1 request body the way h3 v1's `readRawBody` does, and caches a
 * freshly read Node.js stream under `Symbol.for('h3RawBody')` so it stays readable.
 */
function readNodeRawBody(event: H3NodeEvent): Promise<unknown> {
	const req = event.node.req;
	const source =
		readProperty(event, '_requestBody') ||
		readProperty(readProperty(readProperty(event, 'web'), 'request'), 'body') ||
		readProperty(req, kH3RawBody) ||
		readProperty(req, 'rawBody') ||
		readProperty(req, 'body');
	if (source) {
		return Promise.resolve(source);
	}
	if (
		!Number.parseInt(req.headers['content-length'] || '') &&
		!/\bchunked\b/i.test(String(req.headers['transfer-encoding'] ?? ''))
	) {
		return Promise.resolve(undefined);
	}
	const promise = readNodeStream(req);
	Reflect.set(req, kH3RawBody, promise);
	return promise;
}

async function readNodeStream(
	stream: AsyncIterable<Uint8Array | string>
): Promise<Uint8Array> {
	const chunks: Uint8Array[] = [];
	let length = 0;
	for await (const chunk of stream) {
		const bytes =
			typeof chunk === 'string' ? new TextEncoder().encode(chunk) : chunk;
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
async function toBodyReader(
	source: unknown,
	contentType: string
): Promise<Response> {
	if (source instanceof FormData || source instanceof URLSearchParams) {
		// Response derives a matching content-type (and multipart boundary) itself.
		return new Response(source);
	}
	let body: BodyInit;
	if (typeof source === 'string' || source instanceof Uint8Array) {
		body = source as BodyInit;
	} else if (source instanceof ReadableStream) {
		body = source;
	} else if (
		source !== null &&
		typeof source === 'object' &&
		Symbol.asyncIterator in source
	) {
		body = (await readNodeStream(
			source as AsyncIterable<Uint8Array>
		)) as BodyInit;
	} else {
		body = String(source);
	}
	return new Response(body, { headers: { 'content-type': contentType } });
}

async function readBodyField(
	event: H3EventLike,
	contentType: string,
	fieldName: string
): Promise<unknown> {
	const isJson = contentType.includes('application/json');
	const isMultipart = contentType.includes('multipart/form-data');
	const isUrlEncoded = contentType.includes(
		'application/x-www-form-urlencoded'
	);
	if (!isJson && !isMultipart && !isUrlEncoded) {
		return undefined;
	}

	let reader: Request | Response;
	if (isWebEvent(event)) {
		// Read a clone so handlers after the middleware can still read the body.
		reader = event.req.clone();
	} else {
		if (!['DELETE', 'PATCH', 'POST', 'PUT'].includes(event.node.req.method!)) {
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
		let formData: FormData;
		try {
			formData = await reader.formData();
		} catch {
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
	let body: unknown;
	try {
		body = JSON.parse(text);
	} catch {
		throw new AltchaHTTPError(400, 'Invalid JSON body');
	}
	return readOwnProperty(body, fieldName);
}

export function create(options: AltchaOptions) {
	const {
		createChallengeParameters,
		deriveKey,
		fieldName = 'altcha',
		hmacSignatureSecret,
		hmacKeySignatureSecret,
		setCookie,
		store,
		verifyServer: verifyServerOptions,
	} = options;

	const challengeHandler = async (event: H3EventLike) => {
		if (!deriveKey || !createChallengeParameters || !hmacSignatureSecret) {
			throw new AltchaHTTPError(
				500,
				'deriveKey, createChallengeParameters and hmacSignatureSecret are required to generate challenges. Omit challengeHandler when relying on Sentinel to issue challenges.'
			);
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

	const verifyHandler = async (event: H3EventLike) => {
		return await verify(
			await getPayloadFromEvent(event),
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store
		);
	};

	const getPayloadFromEvent = async (
		event: H3EventLike,
		cookieName?: string
	): Promise<string | undefined> => {
		if (cookieName) {
			return getCookie(event, cookieName);
		}
		const payload = await readBodyField(
			event,
			getRequestHeader(event, 'content-type') ?? '',
			fieldName
		);
		return typeof payload === 'string' ? payload : undefined;
	};

	const middleware = (options: AltchaMiddlewareOptions = {}) => {
		const { throwOnFailure = true } = options;

		return async (event: H3EventLike): Promise<void> => {
			const { error, payload, verification } = await verify(
				await getPayloadFromEvent(event, setCookie?.name),
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store,
				verifyServerOptions
			);

			const altcha: AltchaResult = { error, payload, verification };
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
