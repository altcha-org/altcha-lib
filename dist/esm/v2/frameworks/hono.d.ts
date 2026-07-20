import { randomInt } from '../helpers.js';
import { CappedMap } from '../capped-map.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
import type { Context, Env, MiddlewareHandler } from 'hono';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare module 'hono' {
    interface ContextVariableMap {
        altcha?: AltchaResult;
    }
}
export declare function create(options: AltchaOptions): {
    challengeHandler: <E extends Env, P extends string>(c: Context<E, P>) => Promise<Response & import("hono").TypedResponse<{
        codeChallenge?: {
            image: string;
            audio?: string | undefined;
            length?: number | undefined;
        } | undefined;
        parameters: {
            algorithm: string;
            nonce: string;
            salt: string;
            cost: number;
            keyLength: number;
            keyPrefix: string;
            keySignature?: string | undefined;
            memoryCost?: number | undefined;
            parallelism?: number | undefined;
            expiresAt?: number | undefined;
            data?: {
                [x: string]: string | number | boolean | null;
            } | undefined;
        };
        signature?: string | undefined;
        configuration: {
            setCookie: {
                domain?: string | undefined;
                maxAge?: number | undefined;
                path?: string | undefined;
                sameSite?: string | undefined;
                secure?: boolean | undefined;
                name: string;
            };
        } | undefined;
    }, import("hono/utils/http-status").ContentfulStatusCode, "json">>;
    verifyHandler: <E extends Env, P extends string>(c: Context<E, P>) => Promise<Response & import("hono").TypedResponse<{
        error: string | null;
        payload: {
            challenge: {
                signature?: string | undefined;
                parameters: {
                    algorithm: string;
                    nonce: string;
                    salt: string;
                    cost: number;
                    keyLength: number;
                    keyPrefix: string;
                    keySignature?: string | undefined;
                    memoryCost?: number | undefined;
                    parallelism?: number | undefined;
                    expiresAt?: number | undefined;
                    data?: {
                        [x: string]: string | number | boolean | null;
                    } | undefined;
                };
            };
            solution: {
                counter: number;
                derivedKey: string;
                time?: number | undefined;
            };
        } | {
            algorithm: string;
            apiKey?: string | undefined;
            id?: string | undefined;
            signature: string;
            verificationData: string;
            verified: boolean;
        } | null;
        verification: {
            expired: boolean;
            invalidSignature: boolean | null;
            invalidSolution: boolean | null;
            time: number;
            verified: boolean;
        } | {
            apiKey?: string | null | undefined;
            reason?: string | undefined;
            verificationData?: {
                [x: string]: import("hono/utils/types").JSONValue;
                classification?: import("../types.js").ServerClassification | undefined;
                email?: string | undefined;
                expire?: number | undefined;
                fields?: string[] | undefined;
                fieldsHash?: string | undefined;
                id?: string | undefined;
                ipAddress?: string | undefined;
                reasons?: string[] | undefined;
                score?: number | undefined;
                time?: number | undefined;
                verified?: boolean | undefined;
            } | null | undefined;
            verified: boolean;
        } | null;
    }, import("hono/utils/http-status").ContentfulStatusCode, "json">>;
    getPayloadFromContext: (c: Context, cookieName?: string) => Promise<string | undefined>;
    middleware: <E extends Env, P extends string>(options?: AltchaMiddlewareOptions) => MiddlewareHandler<E, P>;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
