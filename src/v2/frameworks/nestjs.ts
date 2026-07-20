import {
	Module,
	Controller,
	Get,
	Post,
	Req,
	Header,
	Injectable,
	NestMiddleware,
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
import type { Request, Response, NextFunction } from 'express';
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

export const Altcha = createParamDecorator(
	(_data: unknown, ctx: ExecutionContext): AltchaResult | undefined => {
		const request = ctx.switchToHttp().getRequest<Request>();
		return request.altcha;
	}
);

export function createAltchaMiddleware(options: AltchaMiddlewareOptions = {}) {
	const { throwOnFailure = true } = options;

	@Injectable()
	class AltchaMiddleware implements NestMiddleware {
		constructor(public readonly altchaService: AltchaService) {}

		async use(req: Request, res: Response, next: NextFunction) {
			const payload = this.altchaService.getPayloadFromRequest(req);
			const {
				error,
				payload: resultPayload,
				verification,
			} = await this.altchaService.verify(payload);
			req.altcha = {
				error,
				payload: resultPayload,
				verification,
			};
			const setCookie = this.altchaService.setCookie;
			if (setCookie) {
				res.clearCookie(setCookie.name);
			}
			if (error && throwOnFailure) {
				throw new HttpException(error, HttpStatus.BAD_REQUEST);
			}
			next();
		}
	}

	return AltchaMiddleware;
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

	getPayloadFromRequest(req: Request, cookieName?: string): string | undefined {
		if (cookieName) {
			return req.cookies?.[cookieName];
		}
		return req.body?.[this.fieldName];
	}

	async verify(payload: string | undefined) {
		return verify(
			payload,
			this.deriveKey,
			this.hmacSignatureSecret,
			this.hmacKeySignatureSecret,
			this.store,
			this.verifyServerOptions
		);
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
	async verifySolution(@Req() req: Request) {
		const payload = this.altchaService.getPayloadFromRequest(req);
		return this.altchaService.verify(payload);
	}
}

@Injectable()
export class AltchaMiddleware implements NestMiddleware {
	constructor(private readonly altchaService: AltchaService) {}
	async use(req: Request, res: Response, next: NextFunction) {
		const payload = this.altchaService.getPayloadFromRequest(
			req,
			this.altchaService.setCookie?.name
		);
		const {
			error,
			payload: resultPayload,
			verification,
		} = await this.altchaService.verify(payload);
		req.altcha = {
			error,
			payload: resultPayload,
			verification,
		};
		const setCookie = this.altchaService.setCookie;
		if (setCookie) {
			res.clearCookie(setCookie.name);
		}
		if (error) {
			throw new HttpException(error, HttpStatus.BAD_REQUEST);
		}
		next();
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
			],
			exports: [AltchaService, AltchaMiddleware],
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
			],
			exports: [AltchaService, AltchaMiddleware],
		};
	}
}

export default AltchaModule;
