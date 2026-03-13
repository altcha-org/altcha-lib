import { deleteCookie, getCookie } from 'hono/cookie';
import { HTTPException } from 'hono/http-exception';
import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';
import type { Context, Env, MiddlewareHandler } from 'hono';

export { CappedMap, deriveHmacKeySecret, randomInt };

export type { AltchaOptions, AltchaResult };

declare module 'hono' {
	interface ContextVariableMap {
		altcha?: AltchaResult;
	}
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
	} = options;

	const challengeHandler = async <E extends Env, P extends string>(
		c: Context<E, P>
	) => {
		return c.json({
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
		});
	};

	const verifyHandler = async <E extends Env, P extends string>(
		c: Context<E, P>
	) => {
		return c.json(
			await verify(
				await getPayloadFromContext(c),
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store
			)
		);
	};

	const getPayloadFromContext = async (c: Context, cookieName?: string) => {
		let payload: string | undefined = undefined;
		if (cookieName) {
			payload = getCookie(c, cookieName);
		} else {
			const contentType = c.req.header('content-type') ?? '';
			let body: Record<string, unknown> | null = null;
			if (contentType.includes('application/json')) {
				body = await c.req.json();
			} else if (
				contentType.includes('multipart/form-data') ||
				contentType.includes('application/x-www-form-urlencoded')
			) {
				body = await c.req.parseBody();
			}
			payload = body?.[fieldName] as string;
		}
		return payload;
	};

	const middleware = <E extends Env, P extends string>(
		options: AltchaMiddlewareOptions = {}
	): MiddlewareHandler<E, P> => {
		const { throwOnFailure = true } = options;
		return async (c, next) => {
			const { error, payload, verification } = await verify(
				await getPayloadFromContext(c, setCookie?.name),
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store
			);
			c.set('altcha', {
				error,
				payload,
				verification,
			});
			if (setCookie) {
				deleteCookie(c, setCookie.name);
			}
			if (error && throwOnFailure) {
				throw new HTTPException(403, {
					message: error,
				});
			}
			return next();
		};
	};

	return {
		challengeHandler,
		verifyHandler,
		getPayloadFromContext,
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
