import { Request, Response, NextFunction } from 'express';
import { createChallenge } from '../pow.js';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type {
	AltchaMiddlewareOptions,
	AltchaOptions,
	AltchaResult,
} from './types.js';

export { CappedMap, deriveHmacKeySecret, randomInt };

export type { AltchaOptions, AltchaResult };

const asyncHandler =
	(fn: (req: Request, res: Response, next: NextFunction) => Promise<void>) =>
	(req: Request, res: Response, next: NextFunction) => {
		fn(req, res, next).catch(next);
	};

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

	const challengeHandler = asyncHandler(async (req, res) => {
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
		res.set('Cache-Control', 'no-store').json({
			configuration: setCookie
				? {
						setCookie,
					}
				: undefined,
			...challenge,
		});
	});

	const verifyHandler = asyncHandler(async (req, res) => {
		const payload = await getPayloadFromRequest(req);
		const result = await verify(
			payload,
			deriveKey,
			hmacSignatureSecret,
			hmacKeySignatureSecret,
			store,
			verifyServerOptions
		);
		res.json(result);
	});

	const getPayloadFromRequest = async (
		req: Request,
		cookieName?: string
	): Promise<string | undefined> => {
		if (cookieName) {
			return req.cookies?.[cookieName];
		}
		return req.body?.[fieldName];
	};

	const middleware = (options: AltchaMiddlewareOptions = {}) => {
		const { throwOnFailure = true } = options;
		return asyncHandler(
			async (
				req: Request,
				res: Response<
					unknown,
					{
						altcha?: AltchaResult;
					}
				>,
				next
			) => {
				const payload = await getPayloadFromRequest(req, setCookie?.name);
				const {
					error,
					payload: resultPayload,
					verification,
				} = await verify(
					payload,
					deriveKey,
					hmacSignatureSecret,
					hmacKeySignatureSecret,
					store,
					verifyServerOptions
				);
				res.locals.altcha = {
					error,
					payload: resultPayload,
					verification,
				};
				if (setCookie) {
					res.clearCookie(setCookie.name);
				}
				if (error && throwOnFailure) {
					throw Object.assign(new Error(error), { status: 403 });
				}
				next();
			}
		);
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
