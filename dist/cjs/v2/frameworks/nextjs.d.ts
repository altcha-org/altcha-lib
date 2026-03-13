import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
export declare function create(options: AltchaOptions): {
    challengeHandler: (_req: Request) => Promise<Response>;
    withMiddleware: (handler: (req: Request) => Promise<Response> | Response, options?: AltchaMiddlewareOptions) => (req: Request) => Promise<Response>;
    verifyHandler: (req: Request) => Promise<Response>;
    getPayloadFromRequest: (req: Request, cookieName?: string) => Promise<string | undefined>;
    middleware: (req: Request, throwOnFailure?: boolean) => Promise<Response | AltchaResult>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
