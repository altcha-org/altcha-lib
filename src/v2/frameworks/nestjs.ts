import {
	Module,
	Controller,
	Get,
	Post,
	Req,
	Header,
	Injectable,
	NestMiddleware,
	CanActivate,
	DynamicModule,
	Inject,
	HttpException,
	HttpStatus,
	createParamDecorator,
	ExecutionContext,
	InjectionToken,
	OptionalFactoryDependency,
	ForwardReference,
	Type,
} from '@nestjs/common';
import { randomInt } from '../helpers.js';
import { createChallenge } from '../pow.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type { DeriveKeyFunction, SetCookieOptions } from '../types.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
	AltchaVerifyServerOptions,
	RequireField,
	Store,
} from './types.js';

export { CappedMap, deriveHmacKeySecret, randomInt };

export type { AltchaOptions, AltchaResult };

const ALTCHA_OPTIONS = Symbol('ALTCHA_OPTIONS');

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace Express {
		interface Request {
			altcha?: AltchaResult;
		}
	}
}

/**
 * Minimal request shape shared by every HTTP adapter NestJS supports.
 *
 * With the Express adapter this is an `express.Request`; with the Fastify
 * adapter middleware receives the raw `http.IncomingMessage` (no `body` or
 * `cookies`), while guards receive the `FastifyRequest`. Only the members the
 * integration actually touches are declared here so a single code path works
 * for all of them.
 */
export interface AltchaRequest {
	altcha?: AltchaResult;
	body?: Record<string, unknown> | null;
	cookies?: Record<string, string | undefined>;
	headers?: Record<string, string | string[] | undefined>;
}

/**
 * Minimal response shape used to clear the ALTCHA cookie across adapters.
 *
 * Express exposes `clearCookie`, a Fastify reply exposes `header`, and the raw
 * `http.ServerResponse` handed to Fastify middleware only exposes `setHeader` /
 * `getHeader`. The cookie helper feature-detects whichever is available.
 */
export interface AltchaResponse {
	clearCookie?: (name: string, options?: Record<string, unknown>) => unknown;
	header?: (name: string, value: string) => unknown;
	setHeader?: (name: string, value: string | string[]) => unknown;
	getHeader?: (name: string) => number | string | string[] | undefined;
}

type NextFunction = (error?: unknown) => void;

/**
 * Reads request cookies without assuming a cookie-parser is installed.
 * Prefers a parsed `cookies` object (Express `cookie-parser`, `@fastify/cookie`)
 * and falls back to parsing the raw `Cookie` header otherwise.
 */
function readCookies(req: AltchaRequest): Record<string, string | undefined> {
	if (req.cookies && typeof req.cookies === 'object') {
		return req.cookies;
	}
	const header = req.headers?.cookie;
	const raw = Array.isArray(header) ? header.join('; ') : header;
	if (!raw) {
		return {};
	}
	const out: Record<string, string> = {};
	for (const pair of raw.split(';')) {
		const eq = pair.indexOf('=');
		if (eq === -1) {
			continue;
		}
		const key = pair.slice(0, eq).trim();
		if (!key) {
			continue;
		}
		const value = pair.slice(eq + 1).trim();
		try {
			out[key] = decodeURIComponent(value);
		} catch {
			out[key] = value;
		}
	}
	return out;
}

/**
 * Clears the ALTCHA cookie regardless of the underlying HTTP adapter.
 * Falls back to emitting an expiring `Set-Cookie` header when no framework
 * helper is available (e.g. the raw `http.ServerResponse` seen by Fastify
 * middleware).
 */
function clearAltchaCookie(
	res: AltchaResponse | undefined,
	name: string,
	path = '/'
): void {
	if (!res) {
		return;
	}
	if (typeof res.clearCookie === 'function') {
		res.clearCookie(name, { path: path || '/' });
		return;
	}
	const cookie = `${name}=; Path=${path || '/'}; Max-Age=0`;
	if (typeof res.header === 'function') {
		res.header('Set-Cookie', cookie);
		return;
	}
	if (typeof res.setHeader === 'function') {
		const existing =
			typeof res.getHeader === 'function'
				? res.getHeader('Set-Cookie')
				: undefined;
		if (Array.isArray(existing)) {
			res.setHeader('Set-Cookie', [...existing, cookie]);
		} else if (typeof existing === 'string' && existing) {
			res.setHeader('Set-Cookie', [existing, cookie]);
		} else {
			res.setHeader('Set-Cookie', cookie);
		}
	}
}

export const Altcha = createParamDecorator(
	(_data: unknown, ctx: ExecutionContext): AltchaResult | undefined => {
		const request = ctx.switchToHttp().getRequest<AltchaRequest>();
		return request.altcha;
	}
);

export function createAltchaMiddleware(options: AltchaMiddlewareOptions = {}) {
	const { throwOnFailure = true } = options;

	@Injectable()
	class AltchaMiddleware implements NestMiddleware {
		constructor(public readonly altchaService: AltchaService) {}

		async use(req: AltchaRequest, res: AltchaResponse, next: NextFunction) {
			const { error } = await this.altchaService.attachResult(req, res);
			if (error && throwOnFailure) {
				throw new HttpException(error, HttpStatus.BAD_REQUEST);
			}
			next();
		}
	}

	return AltchaMiddleware;
}

/**
 * Guard variant of the ALTCHA middleware.
 *
 * Prefer this over {@link createAltchaMiddleware} when running on the Fastify
 * adapter: Fastify middleware runs before the body is parsed, so a payload sent
 * in the request body is not visible to middleware. Guards run after body
 * parsing on every adapter, so body- and cookie-delivered payloads both work.
 */
export function createAltchaGuard(options: AltchaMiddlewareOptions = {}) {
	const { throwOnFailure = true } = options;

	@Injectable()
	class AltchaGuard implements CanActivate {
		constructor(public readonly altchaService: AltchaService) {}

		async canActivate(context: ExecutionContext): Promise<boolean> {
			const http = context.switchToHttp();
			const req = http.getRequest<AltchaRequest>();
			const res = http.getResponse<AltchaResponse>();
			const { error } = await this.altchaService.attachResult(req, res);
			if (error && throwOnFailure) {
				throw new HttpException(error, HttpStatus.BAD_REQUEST);
			}
			return true;
		}
	}

	return AltchaGuard;
}

@Injectable()
export class AltchaService {
	private readonly hmacSignatureSecret?: string;
	private readonly hmacKeySignatureSecret?: string;
	private readonly createChallengeParameters: AltchaOptions['createChallengeParameters'];
	private readonly deriveKey?: DeriveKeyFunction;
	private readonly fieldName: string;
	private readonly setCookieOptions?: RequireField<SetCookieOptions, 'name'>;
	private readonly store?: Store;
	private readonly verifyServerOptions?: AltchaVerifyServerOptions;

	constructor(@Inject(ALTCHA_OPTIONS) options: AltchaOptions) {
		this.hmacSignatureSecret = options.hmacSignatureSecret;
		this.hmacKeySignatureSecret = options.hmacKeySignatureSecret;
		this.createChallengeParameters = options.createChallengeParameters;
		this.deriveKey = options.deriveKey;
		this.fieldName = options.fieldName || 'altcha';
		this.setCookieOptions = options.setCookie;
		this.store = options.store;
		this.verifyServerOptions = options.verifyServer;
	}

	get setCookie(): RequireField<SetCookieOptions, 'name'> | undefined {
		return this.setCookieOptions;
	}

	async getChallenge() {
		const { createChallengeParameters, deriveKey } = this;
		if (!deriveKey || !createChallengeParameters) {
			throw new HttpException(
				'deriveKey and createChallengeParameters are required to generate challenges. Omit the /challenge route when relying on Sentinel to issue challenges.',
				HttpStatus.INTERNAL_SERVER_ERROR
			);
		}
		const challenge = await createChallenge({
			deriveKey,
			hmacSignatureSecret: this.hmacSignatureSecret,
			hmacKeySignatureSecret: this.hmacKeySignatureSecret,
			...createChallengeParameters(),
		});
		return {
			configuration: this.setCookieOptions
				? { setCookie: this.setCookieOptions }
				: undefined,
			...challenge,
		};
	}

	getPayloadFromRequest(
		req: AltchaRequest,
		cookieName?: string
	): string | undefined {
		if (cookieName) {
			return readCookies(req)[cookieName];
		}
		const value = req.body?.[this.fieldName];
		return typeof value === 'string' ? value : undefined;
	}

	async verify(
		payload: string | undefined,
		options: { allowRemote?: boolean } = {}
	) {
		return verify(
			payload,
			this.deriveKey,
			this.hmacSignatureSecret,
			this.hmacKeySignatureSecret,
			this.store,
			options.allowRemote ? this.verifyServerOptions : undefined
		);
	}

	/**
	 * Verifies the payload carried by `req` (body field or configured cookie),
	 * stores the outcome on `req.altcha`, and clears the ALTCHA cookie on `res`
	 * when a cookie is configured. Shared by the middleware and the guard.
	 */
	async attachResult(
		req: AltchaRequest,
		res?: AltchaResponse
	): Promise<AltchaResult> {
		const payload = this.getPayloadFromRequest(req, this.setCookie?.name);
		const {
			error,
			payload: resultPayload,
			verification,
		} = await this.verify(payload, { allowRemote: true });
		const result: AltchaResult = {
			error,
			payload: resultPayload,
			verification,
		};
		req.altcha = result;
		if (this.setCookie) {
			clearAltchaCookie(res, this.setCookie.name, this.setCookie.path);
		}
		return result;
	}
}

@Controller('altcha')
export class AltchaController {
	constructor(private readonly altchaService: AltchaService) {}

	@Get('challenge')
	@Header('Cache-Control', 'no-store')
	async getChallenge() {
		return this.altchaService.getChallenge();
	}

	@Post('verify')
	async verifySolution(@Req() req: AltchaRequest) {
		const payload = this.altchaService.getPayloadFromRequest(req);
		return this.altchaService.verify(payload);
	}
}

@Injectable()
export class AltchaMiddleware implements NestMiddleware {
	constructor(private readonly altchaService: AltchaService) {}
	async use(req: AltchaRequest, res: AltchaResponse, next: NextFunction) {
		const { error } = await this.altchaService.attachResult(req, res);
		if (error) {
			throw new HttpException(error, HttpStatus.BAD_REQUEST);
		}
		next();
	}
}

@Injectable()
export class AltchaGuard implements CanActivate {
	constructor(private readonly altchaService: AltchaService) {}
	async canActivate(context: ExecutionContext): Promise<boolean> {
		const http = context.switchToHttp();
		const req = http.getRequest<AltchaRequest>();
		const res = http.getResponse<AltchaResponse>();
		const { error } = await this.altchaService.attachResult(req, res);
		if (error) {
			throw new HttpException(error, HttpStatus.BAD_REQUEST);
		}
		return true;
	}
}

@Module({})
export class AltchaModule {
	static register(options: AltchaOptions): DynamicModule {
		return {
			module: AltchaModule,
			controllers: [AltchaController],
			providers: [
				{
					provide: ALTCHA_OPTIONS,
					useValue: options,
				},
				AltchaService,
				AltchaMiddleware,
				AltchaGuard,
			],
			exports: [AltchaService, AltchaMiddleware, AltchaGuard],
		};
	}

	static registerAsync(asyncOptions: {
		useFactory: (...args: unknown[]) => Promise<AltchaOptions> | AltchaOptions;
		inject?: (InjectionToken | OptionalFactoryDependency)[];
		imports?: (
			| DynamicModule
			| Type<unknown>
			| ForwardReference<unknown>
			| Promise<DynamicModule>
		)[];
	}): DynamicModule {
		return {
			module: AltchaModule,
			imports: asyncOptions.imports ?? [],
			controllers: [AltchaController],
			providers: [
				{
					provide: ALTCHA_OPTIONS,
					useFactory: asyncOptions.useFactory,
					inject: asyncOptions.inject ?? [],
				},
				AltchaService,
				AltchaMiddleware,
				AltchaGuard,
			],
			exports: [AltchaService, AltchaMiddleware, AltchaGuard],
		};
	}
}

export default AltchaModule;
