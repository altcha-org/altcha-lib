import { randomInt } from '../helpers.js';
import { createChallenge } from '../pow.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';

export { CappedMap, deriveHmacKeySecret, randomInt };

export type { AltchaOptions, AltchaResult };

function getCookieFromRequest(req: Request, name: string): string | undefined {
	const header = req.headers.get('cookie');
	if (!header) {
		return undefined;
	}
	const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
	return match ? decodeURIComponent(match[1]) : undefined;
}

function deleteCookie(res: Response, name: string, path?: string) {
	res.headers.append('Set-Cookie', `${name}=; Path=${path ?? '/'}; Max-Age=0`);
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

	// eslint-disable-next-line @typescript-eslint/no-unused-vars
	async function challengeHandler(_req: Request): Promise<Response> {
		if (!deriveKey || !createChallengeParameters) {
			throw new Error(
				'deriveKey and createChallengeParameters are required to generate challenges. Omit challengeHandler when relying on Sentinel to issue challenges.'
			);
		}
		const challenge = await createChallenge({
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			...createChallengeParameters(),
		});
		const body = {
			configuration: setCookie
				? {
						setCookie,
					}
				: undefined,
			...challenge,
		};
		const response = Response.json(body, {
			headers: { 'Cache-Control': 'no-store' },
		});
		return response;
	}

	async function verifyHandler(req: Request): Promise<Response> {
		const payload = await getPayloadFromRequest(req);
		const result = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store,
			verifyServerOptions
		);

		return Response.json(result);
	}

	async function getPayloadFromRequest(
		req: Request,
		cookieName?: string
	): Promise<string | undefined> {
		let payload: string | undefined = undefined;
		if (cookieName) {
			payload = getCookieFromRequest(req, cookieName);
		} else {
			const contentType = req.headers.get('content-type') ?? '';
			let body: Record<string, unknown> | null = null;
			if (contentType.includes('application/json')) {
				body = await req.json();
			} else if (
				contentType.includes('multipart/form-data') ||
				contentType.includes('application/x-www-form-urlencoded')
			) {
				body = Object.fromEntries((await req.formData()).entries());
			}
			payload = body?.[fieldName] as string;
		}
		return payload;
	}

	async function middleware(
		req: Request,
		throwOnFailure: boolean = true
	): Promise<Response | AltchaResult> {
		const payload = await getPayloadFromRequest(req, setCookie?.name);
		const {
			error,
			payload: verifiedPayload,
			verification,
		} = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store,
			verifyServerOptions
		);
		const result: AltchaResult = {
			error,
			payload: verifiedPayload,
			verification,
		};
		const response = Response.json(result);
		if (setCookie) {
			deleteCookie(response, setCookie.name, setCookie.path);
		}
		if (error && throwOnFailure) {
			return Response.json({ error }, { status: 403 });
		}
		return response;
	}

	function withMiddleware(
		handler: (req: Request) => Promise<Response> | Response,
		options: AltchaMiddlewareOptions = {}
	) {
		const { throwOnFailure = true } = options;
		return async (req: Request): Promise<Response> => {
			const result = await middleware(req, throwOnFailure);
			// If middleware returned a Response, it means verification failed
			if (result instanceof Response) {
				return result;
			}
			// Attach the result to the request for the handler to access
			(req as { __altcha?: AltchaResult }).__altcha = result;
			return handler(req);
		};
	}

	return {
		challengeHandler,
		withMiddleware,
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
