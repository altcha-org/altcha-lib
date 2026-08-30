import { NestMiddleware, CanActivate, DynamicModule, ExecutionContext, InjectionToken, OptionalFactoryDependency, ForwardReference, Type } from '@nestjs/common';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type { SetCookieOptions } from '../types.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult, RequireField } from './types.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
declare global {
    namespace Express {
        interface Request {
            altcha?: AltchaResult;
        }
    }
}
/**
 * Minimal request shape shared by every HTTP adapter NestJS supports.
 *
 * With the Express adapter this is an `express.Request`; with the Fastify
 * adapter middleware receives the raw `http.IncomingMessage` (no `body` or
 * `cookies`), while guards receive the `FastifyRequest`. Only the members the
 * integration actually touches are declared here so a single code path works
 * for all of them.
 */
export interface AltchaRequest {
    altcha?: AltchaResult;
    body?: Record<string, unknown> | null;
    cookies?: Record<string, string | undefined>;
    headers?: Record<string, string | string[] | undefined>;
}
/**
 * Minimal response shape used to clear the ALTCHA cookie across adapters.
 *
 * Express exposes `clearCookie`, a Fastify reply exposes `header`, and the raw
 * `http.ServerResponse` handed to Fastify middleware only exposes `setHeader` /
 * `getHeader`. The cookie helper feature-detects whichever is available.
 */
export interface AltchaResponse {
    clearCookie?: (name: string, options?: Record<string, unknown>) => unknown;
    header?: (name: string, value: string) => unknown;
    setHeader?: (name: string, value: string | string[]) => unknown;
    getHeader?: (name: string) => number | string | string[] | undefined;
}
type NextFunction = (error?: unknown) => void;
export declare const Altcha: (...dataOrPipes: unknown[]) => ParameterDecorator;
export declare function createAltchaMiddleware(options?: AltchaMiddlewareOptions): {
    new (altchaService: AltchaService): {
        readonly altchaService: AltchaService;
        use(req: AltchaRequest, res: AltchaResponse, next: NextFunction): Promise<void>;
    };
};
/**
 * Guard variant of the ALTCHA middleware.
 *
 * Prefer this over {@link createAltchaMiddleware} when running on the Fastify
 * adapter: Fastify middleware runs before the body is parsed, so a payload sent
 * in the request body is not visible to middleware. Guards run after body
 * parsing on every adapter, so body- and cookie-delivered payloads both work.
 */
export declare function createAltchaGuard(options?: AltchaMiddlewareOptions): {
    new (altchaService: AltchaService): {
        readonly altchaService: AltchaService;
        canActivate(context: ExecutionContext): Promise<boolean>;
    };
};
export declare class AltchaService {
    private readonly hmacSignatureSecret?;
    private readonly hmacKeySignatureSecret?;
    private readonly createChallengeParameters;
    private readonly deriveKey?;
    private readonly fieldName;
    private readonly setCookieOptions?;
    private readonly store?;
    private readonly verifyServerOptions?;
    constructor(options: AltchaOptions);
    get setCookie(): RequireField<SetCookieOptions, 'name'> | undefined;
    getChallenge(): Promise<{
        codeChallenge?: import("../types.js").CodeChallenge;
        parameters: import("../types.js").ChallengeParameters;
        signature?: string;
        configuration: {
            setCookie: RequireField<SetCookieOptions, "name">;
        } | undefined;
    }>;
    getPayloadFromRequest(req: AltchaRequest, cookieName?: string): string | undefined;
    verify(payload: string | undefined, options?: {
        allowRemote?: boolean;
    }): Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | import("../types.js").VerifyServerResult | null;
    }>;
    /**
     * Verifies the payload carried by `req` (body field or configured cookie),
     * stores the outcome on `req.altcha`, and clears the ALTCHA cookie on `res`
     * when a cookie is configured. Shared by the middleware and the guard.
     */
    attachResult(req: AltchaRequest, res?: AltchaResponse): Promise<AltchaResult>;
}
export declare class AltchaController {
    private readonly altchaService;
    constructor(altchaService: AltchaService);
    getChallenge(): Promise<{
        codeChallenge?: import("../types.js").CodeChallenge;
        parameters: import("../types.js").ChallengeParameters;
        signature?: string;
        configuration: {
            setCookie: RequireField<SetCookieOptions, "name">;
        } | undefined;
    }>;
    verifySolution(req: AltchaRequest): Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | import("../types.js").VerifyServerResult | null;
    }>;
}
export declare class AltchaMiddleware implements NestMiddleware {
    private readonly altchaService;
    constructor(altchaService: AltchaService);
    use(req: AltchaRequest, res: AltchaResponse, next: NextFunction): Promise<void>;
}
export declare class AltchaGuard implements CanActivate {
    private readonly altchaService;
    constructor(altchaService: AltchaService);
    canActivate(context: ExecutionContext): Promise<boolean>;
}
export declare class AltchaModule {
    static register(options: AltchaOptions): DynamicModule;
    static registerAsync(asyncOptions: {
        useFactory: (...args: unknown[]) => Promise<AltchaOptions> | AltchaOptions;
        inject?: (InjectionToken | OptionalFactoryDependency)[];
        imports?: (DynamicModule | Type<unknown> | ForwardReference<unknown> | Promise<DynamicModule>)[];
    }): DynamicModule;
}
export default AltchaModule;
