import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
import type { H3Event } from 'h3';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare module 'h3' {
    interface H3EventContext {
        altcha?: AltchaResult;
    }
}
export declare function create(options: AltchaOptions): {
    challengeHandler: import("h3").EventHandlerWithFetch<import("h3").EventHandlerRequest, Promise<{
        codeChallenge?: import("../types.js").CodeChallenge;
        parameters: import("../types.js").ChallengeParameters;
        signature?: string;
        configuration: {
            setCookie: import("./types.js").RequireField<import("../types.js").SetCookieOptions, "name">;
        } | undefined;
    }>>;
    verifyHandler: import("h3").EventHandlerWithFetch<import("h3").EventHandlerRequest, Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | null;
    }>>;
    getPayloadFromEvent: (event: H3Event, cookieName?: string) => Promise<string | undefined>;
    middleware: (options?: AltchaMiddlewareOptions) => import("h3").EventHandlerWithFetch<import("h3").EventHandlerRequest, Promise<void>>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
