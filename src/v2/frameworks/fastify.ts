import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';
import type { FastifyRequest, FastifyReply } from 'fastify';

export { CappedMap, deriveHmacKeySecret, randomInt };

export type { AltchaOptions, AltchaResult };

declare module 'fastify' {
	interface FastifyRequest {
		altcha?: AltchaResult;
	}
}

export function create(options: AltchaOptions) {
	const {
		createChallengeParameters,
		deriveKey,
		hmacSignatureSecret,
		hmacKeySignatureSecret,
		setCookie,
		store,
	} = options;

	const deleteCookie = (
		reply: FastifyReply,
		name: string,
		path: string = '/'
	) => {
		reply.header('Set-Cookie', `${name}=; Path=${path ?? '/'}; Max-Age=0`);
	};

	const parseCookies = (request: FastifyRequest): Record<string, string> => {
		if ('cookies' in request) {
			return request.cookies as Record<string, string>;
		}
		const header = request.headers.cookie;
		if (!header) {
			return {};
		}
		return Object.fromEntries(
			header.split(';').map((pair) => {
				const [key, ...rest] = pair.trim().split('=');
				return [key, decodeURIComponent(rest.join('='))];
			})
		);
	};

	const getPayloadFromRequest = async (
		request: FastifyRequest,
		cookieName?: string
	): Promise<string | undefined> => {
		if (cookieName) {
			return parseCookies(request)[cookieName];
		}
		return (request.body as Record<string, string>)?.altcha;
	};

	const challengeHandler = async (
		request: FastifyRequest,
		reply: FastifyReply
	) => {
		const challenge = await createChallenge({
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			...createChallengeParameters(),
		});
		return reply.send({
			configuration: setCookie
				? {
						setCookie,
					}
				: undefined,
			...challenge,
		});
	};

	const verifyHandler = async (
		request: FastifyRequest,
		reply: FastifyReply
	) => {
		const payload = await getPayloadFromRequest(request);
		const result = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store
		);
		return reply.send(result);
	};

	const middleware = (options: AltchaMiddlewareOptions = {}) => {
		const { throwOnFailure = true } = options;
		return async (request: FastifyRequest, reply: FastifyReply) => {
			const payload = await getPayloadFromRequest(request, setCookie?.name);
			const {
				error,
				payload: resultPayload,
				verification,
			} = await verify(
				payload,
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store
			);
			request.altcha = {
				error,
				payload: resultPayload,
				verification,
			};
			if (setCookie) {
				deleteCookie(reply, setCookie.name, setCookie.path);
			}
			if (error && throwOnFailure) {
				return reply.code(403).send({ error });
			}
		};
	};

	return {
		challengeHandler,
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
