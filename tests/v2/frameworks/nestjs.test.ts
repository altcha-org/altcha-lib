import 'reflect-metadata';
import { describe, expect, test, vi } from 'vitest';
import type { FactoryProvider } from '@nestjs/common';
import {
	AltchaController,
	AltchaGuard,
	AltchaMiddleware,
	AltchaModule,
	AltchaService,
	createAltchaGuard,
	createAltchaMiddleware,
} from '../../../src/v2/frameworks/nestjs.js';
import { deriveKey } from '../../../src/v2/algorithms/pbkdf2.js';
import { createChallenge, solveChallenge } from '../../../src/v2/pow.js';
import type { AltchaOptions } from '../../../src/v2/frameworks/types.js';

const hmacSignatureSecret = 'secret.key';

function baseOptions(overrides: Partial<AltchaOptions> = {}): AltchaOptions {
	return {
		createChallengeParameters: () => ({
			algorithm: 'PBKDF2/SHA-256',
			cost: 10,
			counter: 10,
		}),
		deriveKey,
		hmacSignatureSecret,
		...overrides,
	};
}

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

/** Express-style response: exposes `clearCookie`. */
function expressResponse() {
	return { clearCookie: vi.fn() };
}

/** Fastify reply-style response: exposes `header`. */
function fastifyReply() {
	return { header: vi.fn() };
}

/** Raw `http.ServerResponse`-style response: only `setHeader` / `getHeader`. */
function rawResponse() {
	const headers = new Map<string, string | string[]>();
	return {
		setHeader: vi.fn((name: string, value: string | string[]) => {
			headers.set(name.toLowerCase(), value);
		}),
		getHeader: vi.fn((name: string) => headers.get(name.toLowerCase())),
		headers,
	};
}

function executionContext(req: unknown, res: unknown) {
	return {
		switchToHttp: () => ({
			getRequest: () => req,
			getResponse: () => res,
		}),
	} as never;
}

describe('NestJS', () => {
	describe('AltchaService.getPayloadFromRequest', () => {
		test('reads the payload from a parsed body', () => {
			const service = new AltchaService(baseOptions());
			expect(service.getPayloadFromRequest({ body: { altcha: 'token' } })).toBe(
				'token'
			);
		});

		test('honours a custom fieldName', () => {
			const service = new AltchaService(baseOptions({ fieldName: 'captcha' }));
			expect(
				service.getPayloadFromRequest({ body: { captcha: 'token' } })
			).toBe('token');
		});

		test('returns undefined when the body is missing (Fastify middleware)', () => {
			const service = new AltchaService(baseOptions());
			expect(service.getPayloadFromRequest({})).toBeUndefined();
		});

		test('reads a cookie from a parsed cookies object', () => {
			const service = new AltchaService(baseOptions());
			expect(
				service.getPayloadFromRequest(
					{ cookies: { altcha: 'from-cookie' } },
					'altcha'
				)
			).toBe('from-cookie');
		});

		test('reads a cookie from the raw Cookie header (Fastify raw request)', () => {
			const service = new AltchaService(baseOptions());
			expect(
				service.getPayloadFromRequest(
					{ headers: { cookie: 'a=1; altcha=from-header; b=2' } },
					'altcha'
				)
			).toBe('from-header');
		});

		test('url-decodes raw cookie values', () => {
			const service = new AltchaService(baseOptions());
			expect(
				service.getPayloadFromRequest(
					{ headers: { cookie: 'altcha=a%20b%2Bc' } },
					'altcha'
				)
			).toBe('a b+c');
		});
	});

	describe('AltchaService.attachResult', () => {
		test('stores the verification result on req.altcha', async () => {
			const service = new AltchaService(baseOptions());
			const payload = await createPayload();
			const req: Record<string, unknown> = { body: { altcha: payload } };
			const result = await service.attachResult(req);
			expect(result.error).toBeNull();
			expect(req.altcha).toBe(result);
			expect(result.verification).toMatchObject({ verified: true });
		});

		test('reports a missing payload without throwing', async () => {
			const service = new AltchaService(baseOptions());
			const req: Record<string, unknown> = {};
			const result = await service.attachResult(req);
			expect(result.error).toBe('ALTCHA payload is missing.');
			expect(req.altcha).toBe(result);
		});

		describe('cookie clearing is adapter-agnostic', () => {
			test('Express response uses clearCookie', async () => {
				const service = new AltchaService(
					baseOptions({ setCookie: { name: 'altcha', path: '/' } })
				);
				const res = expressResponse();
				await service.attachResult({ body: {} }, res);
				expect(res.clearCookie).toHaveBeenCalledWith('altcha', { path: '/' });
			});

			test('Fastify reply uses a Set-Cookie header', async () => {
				const service = new AltchaService(
					baseOptions({ setCookie: { name: 'altcha' } })
				);
				const res = fastifyReply();
				await service.attachResult({ body: {} }, res);
				expect(res.header).toHaveBeenCalledWith(
					'Set-Cookie',
					'altcha=; Path=/; Max-Age=0'
				);
			});

			test('raw http.ServerResponse uses setHeader and does not throw', async () => {
				const service = new AltchaService(
					baseOptions({ setCookie: { name: 'altcha', path: '/app' } })
				);
				const res = rawResponse();
				await expect(
					service.attachResult({ headers: {} }, res)
				).resolves.toBeDefined();
				expect(res.setHeader).toHaveBeenCalledWith(
					'Set-Cookie',
					'altcha=; Path=/app; Max-Age=0'
				);
			});

			test('raw http.ServerResponse appends to an existing Set-Cookie', async () => {
				const service = new AltchaService(
					baseOptions({ setCookie: { name: 'altcha' } })
				);
				const res = rawResponse();
				res.setHeader('Set-Cookie', 'session=abc');
				await service.attachResult({ headers: {} }, res);
				expect(res.headers.get('set-cookie')).toEqual([
					'session=abc',
					'altcha=; Path=/; Max-Age=0',
				]);
			});

			test('no cookie is cleared when setCookie is not configured', async () => {
				const service = new AltchaService(baseOptions());
				const res = expressResponse();
				await service.attachResult({ body: {} }, res);
				expect(res.clearCookie).not.toHaveBeenCalled();
			});
		});
	});

	describe('createAltchaGuard()', () => {
		test('passes a valid body payload and exposes the result', async () => {
			const Guard = createAltchaGuard();
			const service = new AltchaService(baseOptions());
			const guard = new Guard(service);
			const payload = await createPayload();
			const req: Record<string, unknown> = { body: { altcha: payload } };
			await expect(guard.canActivate(executionContext(req, {}))).resolves.toBe(
				true
			);
			expect((req.altcha as { error: string | null }).error).toBeNull();
		});

		test('throws a 400 HttpException on a missing payload', async () => {
			const Guard = createAltchaGuard();
			const guard = new Guard(new AltchaService(baseOptions()));
			await expect(
				guard.canActivate(executionContext({ body: {} }, {}))
			).rejects.toMatchObject({
				status: 400,
				message: 'ALTCHA payload is missing.',
			});
		});

		test('throws on an expired challenge', async () => {
			const Guard = createAltchaGuard();
			const guard = new Guard(new AltchaService(baseOptions()));
			const payload = await createPayload({
				expiresAt: new Date(Date.now() - 1_000),
			});
			await expect(
				guard.canActivate(executionContext({ body: { altcha: payload } }, {}))
			).rejects.toMatchObject({ status: 400 });
		});

		test('does not throw when throwOnFailure is false', async () => {
			const Guard = createAltchaGuard({ throwOnFailure: false });
			const guard = new Guard(new AltchaService(baseOptions()));
			const req: Record<string, unknown> = { body: {} };
			await expect(guard.canActivate(executionContext(req, {}))).resolves.toBe(
				true
			);
			expect((req.altcha as { error: string | null }).error).toBe(
				'ALTCHA payload is missing.'
			);
		});

		test('verifies a cookie-delivered payload from the raw Cookie header', async () => {
			const Guard = createAltchaGuard();
			const service = new AltchaService(
				baseOptions({ setCookie: { name: 'altcha' } })
			);
			const guard = new Guard(service);
			const payload = await createPayload();
			const req: Record<string, unknown> = {
				headers: { cookie: `altcha=${encodeURIComponent(payload)}` },
			};
			const res = fastifyReply();
			await expect(guard.canActivate(executionContext(req, res))).resolves.toBe(
				true
			);
			expect((req.altcha as { error: string | null }).error).toBeNull();
			expect(res.header).toHaveBeenCalledWith(
				'Set-Cookie',
				'altcha=; Path=/; Max-Age=0'
			);
		});
	});

	describe('createAltchaMiddleware()', () => {
		test('calls next() on a valid payload', async () => {
			const Middleware = createAltchaMiddleware();
			const middleware = new Middleware(new AltchaService(baseOptions()));
			const payload = await createPayload();
			const req: Record<string, unknown> = { body: { altcha: payload } };
			const next = vi.fn();
			await middleware.use(req, {}, next);
			expect(next).toHaveBeenCalledTimes(1);
			expect((req.altcha as { error: string | null }).error).toBeNull();
		});

		test('throws instead of calling next() on failure', async () => {
			const Middleware = createAltchaMiddleware();
			const middleware = new Middleware(new AltchaService(baseOptions()));
			const next = vi.fn();
			await expect(
				middleware.use({ body: {} }, {}, next)
			).rejects.toMatchObject({ status: 400 });
			expect(next).not.toHaveBeenCalled();
		});

		test('calls next() on failure when throwOnFailure is false', async () => {
			const Middleware = createAltchaMiddleware({ throwOnFailure: false });
			const middleware = new Middleware(new AltchaService(baseOptions()));
			const next = vi.fn();
			await middleware.use({ body: {} }, {}, next);
			expect(next).toHaveBeenCalledTimes(1);
		});
	});

	describe('dependency injection metadata', () => {
		// NestJS resolves constructor dependencies from `design:paramtypes`, which
		// only TypeScript's `emitDecoratorMetadata` produces. Builders that
		// transpile without it (esbuild, and SWC unless `decoratorMetadata` is
		// enabled) drop that metadata, so every injected constructor parameter
		// carries an explicit `@Inject()` token instead.
		const SELF_DECLARED_DEPS_METADATA = 'self:paramtypes';

		function selfDeclaredDeps(target: unknown) {
			return (
				(Reflect.getMetadata(SELF_DECLARED_DEPS_METADATA, target as object) as
					| { index: number; param: unknown }[]
					| undefined) ?? []
			);
		}

		test.each([
			['AltchaController', AltchaController],
			['AltchaMiddleware', AltchaMiddleware],
			['AltchaGuard', AltchaGuard],
			['createAltchaMiddleware()', createAltchaMiddleware()],
			['createAltchaGuard()', createAltchaGuard()],
		])('%s injects AltchaService by explicit token', (_name, target) => {
			expect(selfDeclaredDeps(target)).toEqual([
				{ index: 0, param: AltchaService },
			]);
		});
	});

	describe('AltchaModule.registerAsync()', () => {
		class ConfigService {
			getOrThrow(key: string): string {
				return `value:${key}`;
			}
		}

		function findFactoryProvider(
			module: ReturnType<typeof AltchaModule.registerAsync>
		): FactoryProvider | undefined {
			return module.providers?.find(
				(provider): provider is FactoryProvider =>
					typeof provider === 'object' &&
					provider !== null &&
					'useFactory' in provider
			);
		}

		// Regression test for issue #19: a useFactory declaring typed parameters
		// for its injected providers must type-check without the
		// `(...args: unknown[])` workaround.
		test('accepts a useFactory with typed injected parameters', async () => {
			const module = AltchaModule.registerAsync({
				inject: [ConfigService],
				useFactory: async (config: ConfigService) => ({
					hmacSignatureSecret: config.getOrThrow(
						'ALTCHA_HMAC_SIGNATURE_SECRET'
					),
					createChallengeParameters: () => ({
						algorithm: 'PBKDF2/SHA-256' as const,
						cost: 10,
					}),
					deriveKey,
				}),
			});
			const factoryProvider = findFactoryProvider(module);
			expect(factoryProvider?.inject).toEqual([ConfigService]);
			const options = await factoryProvider?.useFactory(new ConfigService());
			expect(options).toMatchObject({
				hmacSignatureSecret: 'value:ALTCHA_HMAC_SIGNATURE_SECRET',
			});
		});

		test('accepts a useFactory with multiple typed parameters', () => {
			const module = AltchaModule.registerAsync({
				inject: [ConfigService, 'ALTCHA_TOKEN'],
				useFactory: (config: ConfigService, token: string) => ({
					hmacSignatureSecret: config.getOrThrow(token),
					createChallengeParameters: () => ({
						algorithm: 'PBKDF2/SHA-256' as const,
						cost: 10,
					}),
					deriveKey,
				}),
			});
			expect(findFactoryProvider(module)?.inject).toEqual([
				ConfigService,
				'ALTCHA_TOKEN',
			]);
		});

		test('still accepts a zero-argument useFactory', () => {
			const module = AltchaModule.registerAsync({
				useFactory: () => baseOptions(),
			});
			expect(module.module).toBe(AltchaModule);
			expect(findFactoryProvider(module)?.inject).toEqual([]);
		});
	});
});
