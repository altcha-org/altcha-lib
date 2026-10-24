import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
import type { IncomingMessage, ServerResponse } from 'node:http';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare module 'h3' {
    interface H3EventContext {
        altcha?: AltchaResult;
    }
}
/** h3 v2 event: `req` is a web `Request`, `res.headers` the response headers. */
export interface H3WebEvent {
    req: Request;
    res: {
        headers: Headers;
    };
    context: object;
}
/** h3 v1 event: Node.js `req`/`res` under `node`. */
export interface H3NodeEvent {
    node: {
        req: IncomingMessage;
        res: ServerResponse;
    };
    context: object;
}
export type H3EventLike = H3WebEvent | H3NodeEvent;
export declare function create(options: AltchaOptions): {
    challengeHandler: (event: H3EventLike) => Promise<{
        codeChallenge?: import("../types.js").CodeChallenge;
        parameters: import("../types.js").ChallengeParameters;
        signature?: string;
        configuration: {
            setCookie: import("./types.js").RequireField<import("../types.js").SetCookieOptions, "name">;
        } | undefined;
    }>;
    verifyHandler: (event: H3EventLike) => Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | import("../types.js").VerifyServerResult | null;
    }>;
    getPayloadFromEvent: (event: H3EventLike, cookieName?: string) => Promise<string | undefined>;
    middleware: (options?: AltchaMiddlewareOptions) => (event: H3EventLike) => Promise<void>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
