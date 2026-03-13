import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
import type { FastifyRequest, FastifyReply } from 'fastify';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare module 'fastify' {
    interface FastifyRequest {
        altcha?: AltchaResult;
    }
}
export declare function create(options: AltchaOptions): {
    challengeHandler: (request: FastifyRequest, reply: FastifyReply) => Promise<never>;
    verifyHandler: (request: FastifyRequest, reply: FastifyReply) => Promise<never>;
    getPayloadFromRequest: (request: FastifyRequest, cookieName?: string) => Promise<string | undefined>;
    middleware: (options?: AltchaMiddlewareOptions) => (request: FastifyRequest, reply: FastifyReply) => Promise<undefined>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
