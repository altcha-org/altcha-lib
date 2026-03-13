import {
	HTTPError,
	defineEventHandler,
	getCookie,
	deleteCookie,
	readBody,
} from 'h3';
import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';
import type { H3Event } from 'h3';

export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };

declare module 'h3' {
	interface H3EventContext {
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

	const challengeHandler = defineEventHandler(async () => {
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
	});

	const verifyHandler = defineEventHandler(async (event) => {
		return await verify(
			await getPayloadFromEvent(event),
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store
		);
	});

	const getPayloadFromEvent = async (
		event: H3Event,
		cookieName?: string
	): Promise<string | undefined> => {
		let payload: string | undefined = undefined;

		if (cookieName) {
			payload = getCookie(event, cookieName);
		} else {
			const contentType = event.req.headers.get('content-type') ?? '';
			let body: Record<string, unknown> | null | undefined = null;

			if (contentType.includes('application/json')) {
				body = await readBody(event);
			} else if (contentType.includes('multipart/form-data')) {
				const formData = await event.req.formData();
				const value = formData.get(fieldName);
				if (typeof value === 'string') {
					payload = value;
				}
				return payload;
			} else if (contentType.includes('application/x-www-form-urlencoded')) {
				body = await readBody(event);
			}

			payload = body?.[fieldName] as string;
		}

		return payload;
	};

	const middleware = (options: AltchaMiddlewareOptions = {}) => {
		const { throwOnFailure = true } = options;

		return defineEventHandler(async (event) => {
			const { error, payload, verification } = await verify(
				await getPayloadFromEvent(event, setCookie?.name),
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store
			);

			event.context.altcha = {
				error,
				payload,
				verification,
			};

			if (setCookie) {
				deleteCookie(event, setCookie.name);
			}

			if (error && throwOnFailure) {
				throw new HTTPError({ message: error, status: 403 });
			}
		});
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
