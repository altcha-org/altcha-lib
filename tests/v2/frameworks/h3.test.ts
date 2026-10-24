import { once } from 'node:events';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, test } from 'vitest';
import { H3 } from 'h3';
import {
	createApp as createAppV1,
	createRouter as createRouterV1,
	defineEventHandler as defineEventHandlerV1,
	readRawBody as readRawBodyV1,
	toNodeListener as toNodeListenerV1,
} from 'h3-v1';
import { create } from '../../../src/v2/frameworks/h3.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';

/** Shape shared by h3 v1 `H3Error` and h3 v2 `HTTPError`. */
interface AppError {
	message: string;
	statusCode: number;
	unhandled?: boolean;
}

interface TestServer {
	/** Errors passed to the app's `onError` hook. */
	errors: AppError[];
	request(path: string, init?: RequestInit): Promise<Response>;
	close(): Promise<void>;
}

/** Nuxt 4 / Nitro 2 setup: h3 v1 app served by a Node.js HTTP server. */
async function createV1Server(cookieName?: string): Promise<TestServer> {
	const altcha = createAltcha(cookieName);
	const errors: AppError[] = [];
	const app = createAppV1({
		onError(error) {
			errors.push(error);
		},
	});
	const middleware = altcha.middleware();
	const router = createRouterV1()
		.get('/challenge', altcha.challengeHandler)
		.post('/verify', altcha.verifyHandler)
		.post(
			'/submit',
			defineEventHandlerV1(async (event) => {
				await middleware(event);
				return {
					altcha: event.context.altcha,
					body: await readRawBodyV1(event),
				};
			})
		);
	app.use(router);
	const server = createServer(toNodeListenerV1(app));
	server.listen(0, '127.0.0.1');
	await once(server, 'listening');
	const { port } = server.address() as AddressInfo;
	return {
		errors,
		request: (path, init) => fetch(`http://127.0.0.1:${port}${path}`, init),
		close: async () => {
			server.close();
			server.closeAllConnections();
			await once(server, 'close');
		},
	};
}

/** Nitro 3 setup: h3 v2 app handling web requests. */
async function createV2Server(cookieName?: string): Promise<TestServer> {
	const altcha = createAltcha(cookieName);
	const errors: AppError[] = [];
	const middleware = altcha.middleware();
	const app = new H3({
		onError(error) {
			errors.push(error);
		},
	})
		.get('/challenge', altcha.challengeHandler)
		.post('/verify', altcha.verifyHandler)
		.post('/submit', async (event) => {
			await middleware(event);
			return {
				altcha: event.context.altcha,
				body: await event.req.text(),
			};
		});
	return {
		errors,
		request: async (path, init) => app.request(path, init),
		close: async () => {},
	};
}

const bodyEncodings: Record<
	string,
	(payload: string) => Pick<RequestInit, 'body' | 'headers'>
> = {
	json: (payload) => ({
		body: JSON.stringify({ altcha: payload, test: 'test-field' }),
		headers: { 'content-type': 'application/json' },
	}),
	urlencoded: (payload) => ({
		body: new URLSearchParams({ altcha: payload, test: 'test-field' }),
	}),
	multipart: (payload) => {
		const body = new FormData();
		body.set('altcha', payload);
		body.set('test', 'test-field');
		return { body };
	},
};

const hmacSignatureSecret = 'secret.key';

async function createPayload(
	options?: Partial<Parameters<typeof createChallenge>[0]>
) {
	const challenge = await createChallenge({
		algorithm: 'PBKDF2/SHA-256',
		cost: 10,
		counter: 10,
		deriveKey,
		hmacSignatureSecret,
		...options,
	});
	const solution = await solveChallenge({ challenge, deriveKey });
	return btoa(JSON.stringify({ challenge, solution }));
}

function createAltcha(cookieName?: string) {
	return create({
		createChallengeParameters: () => ({
			algorithm: 'PBKDF2/SHA-256',
			cost: 10,
			counter: 10,
		}),
		deriveKey,
		hmacSignatureSecret,
		setCookie: cookieName ? { name: cookieName } : undefined,
	});
}

describe.each([
	['h3 v1', createV1Server],
	['h3 v2', createV2Server],
])('H3 (%s)', (_, createTestServer) => {
	let server: TestServer | undefined;

	afterEach(async () => {
		await server?.close();
		server = undefined;
	});

	test('challengeHandler returns an uncacheable challenge', async () => {
		server = await createTestServer();
		const resp = await server.request('/challenge');
		expect(resp.status).toBe(200);
		expect(resp.headers.get('cache-control')).toBe('no-store');
		const json = await resp.json();
		expect(json.parameters.algorithm).toBe('PBKDF2/SHA-256');
		expect(json.signature).toEqual(expect.any(String));
	});

	test.each(Object.keys(bodyEncodings))(
		'verifyHandler verifies a %s payload',
		async (encoding) => {
			server = await createTestServer();
			const resp = await server.request('/verify', {
				method: 'POST',
				...bodyEncodings[encoding](await createPayload()),
			});
			const json = await resp.json();
			expect(json.error).toBeNull();
			expect(json.verification.verified).toBe(true);
		}
	);

	test.each(Object.keys(bodyEncodings))(
		'middleware accepts a %s payload and leaves the body readable',
		async (encoding) => {
			server = await createTestServer();
			const resp = await server.request('/submit', {
				method: 'POST',
				...bodyEncodings[encoding](await createPayload()),
			});
			expect(resp.status).toBe(200);
			const json = await resp.json();
			expect(json.altcha.verification.verified).toBe(true);
			expect(json.body).toContain('test-field');
		}
	);

	test.each([
		[
			'expired',
			async () =>
				JSON.stringify({
					altcha: await createPayload({
						expiresAt: new Date(Date.now() - 1_000),
					}),
				}),
			'ALTCHA verification failed.',
		],
		['missing', async () => JSON.stringify({}), 'ALTCHA payload is missing.'],
	])(
		'middleware rejects a %s payload with a handled 403',
		async (_, getBody, message) => {
			server = await createTestServer();
			const resp = await server.request('/submit', {
				method: 'POST',
				body: await getBody(),
				headers: { 'content-type': 'application/json' },
			});
			expect(resp.status).toBe(403);
			// A falsy `unhandled` means the app recognized the error as an h3 HTTP error;
			// unrecognized errors are logged and their message is hidden from the client.
			expect(server.errors).toHaveLength(1);
			expect(server.errors[0]).toMatchObject({ message, statusCode: 403 });
			expect(server.errors[0].unhandled).toBeFalsy();
		}
	);

	test('middleware rejects invalid JSON with a 400', async () => {
		server = await createTestServer();
		const resp = await server.request('/submit', {
			method: 'POST',
			body: '{',
			headers: { 'content-type': 'application/json' },
		});
		expect(resp.status).toBe(400);
	});

	test('middleware reads the payload from the cookie and deletes it', async () => {
		server = await createTestServer('altcha');
		const payload = await createPayload();
		const resp = await server.request('/submit', {
			method: 'POST',
			headers: { cookie: `other=1; altcha=${encodeURIComponent(payload)}` },
		});
		expect(resp.status).toBe(200);
		const json = await resp.json();
		expect(json.altcha.verification.verified).toBe(true);
		expect(resp.headers.get('set-cookie')).toMatch(
			/^altcha=; Max-Age=0; Path=\//
		);
	});
});
