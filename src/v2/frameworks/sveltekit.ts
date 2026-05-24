import { error, json, type RequestEvent, type Handle } from '@sveltejs/kit';
import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';

export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };

declare global {
	// eslint-disable-next-line @typescript-eslint/no-namespace
	namespace App {
		interface Locals {
			altcha?: AltchaResult;
		}
	}
}

async function getPayloadFromEvent(
	event: RequestEvent,
	fieldName: string,
	cookieName?: string
): Promise<string | undefined> {
	if (cookieName) {
		return event.cookies.get(cookieName);
	}

	const contentType = event.request.headers.get('content-type') ?? '';
	let body: Record<string, unknown> | null = null;

	if (contentType.includes('application/json')) {
		body = await event.request.json();
	} else if (
		contentType.includes('multipart/form-data') ||
		contentType.includes('application/x-www-form-urlencoded')
	) {
		const formData = await event.request.formData();
		body = Object.fromEntries(formData.entries());
	}

	return body?.[fieldName] as string | undefined;
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

	async function challengeHandler() {
		const challenge = await createChallenge({
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			...createChallengeParameters(),
		});

		return json(
			{
				configuration: setCookie
					? {
							setCookie,
						}
					: undefined,
				...challenge,
			},
			{ headers: { 'Cache-Control': 'no-store' } }
		);
	}

	async function verifyHandler(event: RequestEvent) {
		const payload = await getPayloadFromEvent(event, fieldName);
		const result = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store
		);
		return json(result);
	}

	function createHandle(
		middlewareOptions: AltchaMiddlewareOptions = {}
	): Handle {
		const { throwOnFailure = true } = middlewareOptions;

		return async ({ event, resolve }) => {
			const payload = await getPayloadFromEvent(
				event,
				fieldName,
				setCookie?.name
			);

			const {
				error: verifyError,
				payload: resultPayload,
				verification,
			} = await verify(
				payload,
				deriveKey,
				hmacSignatureSecret,
				hmacKeySignatureSecret,
				store
			);

			event.locals.altcha = {
				error: verifyError,
				payload: resultPayload,
				verification,
			} satisfies AltchaResult;

			if (setCookie) {
				event.cookies.delete(setCookie.name, {
					path: setCookie.path ?? '/',
				});
			}

			if (verifyError && throwOnFailure) {
				error(403, verifyError);
			}

			return resolve(event);
		};
	}

	async function verifyEvent(event: RequestEvent): Promise<AltchaResult> {
		const payload = await getPayloadFromEvent(
			event,
			fieldName,
			setCookie?.name
		);

		const {
			error: verifyError,
			payload: resultPayload,
			verification,
		} = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store
		);

		if (setCookie) {
			event.cookies.delete(setCookie.name, {
				path: setCookie.path ?? '/',
			});
		}

		return {
			error: verifyError,
			payload: resultPayload,
			verification,
		};
	}

	return {
		challengeHandler,
		verifyHandler,
		verifyEvent,
		createHandle,
		getPayloadFromEvent: (event: RequestEvent, cookieName?: string) =>
			getPayloadFromEvent(event, fieldName, cookieName),
		verify,
	};
}

export default {
	CappedMap,
	create,
	deriveHmacKeySecret,
	randomInt,
};
