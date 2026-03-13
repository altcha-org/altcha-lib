import { type RequestEvent, type Handle } from '@sveltejs/kit';
import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare global {
    namespace App {
        interface Locals {
            altcha?: AltchaResult;
        }
    }
}
export declare function create(options: AltchaOptions): {
    challengeHandler: () => Promise<Response>;
    verifyHandler: (event: RequestEvent) => Promise<Response>;
    verifyEvent: (event: RequestEvent) => Promise<AltchaResult>;
    createHandle: (middlewareOptions?: AltchaMiddlewareOptions) => Handle;
    getPayloadFromEvent: (event: RequestEvent, cookieName?: string) => Promise<string | undefined>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
