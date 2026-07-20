import { NestMiddleware, DynamicModule, InjectionToken, OptionalFactoryDependency, ForwardReference, Type } from '@nestjs/common';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type { Request, Response, NextFunction } from 'express';
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
export declare const Altcha: (...dataOrPipes: unknown[]) => ParameterDecorator;
export declare function createAltchaMiddleware(options?: AltchaMiddlewareOptions): {
    new (altchaService: AltchaService): {
        readonly altchaService: AltchaService;
        use(req: Request, res: Response, next: NextFunction): Promise<void>;
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
    getPayloadFromRequest(req: Request, cookieName?: string): string | undefined;
    verify(payload: string | undefined, options?: {
        allowRemote?: boolean;
    }): Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | import("../types.js").VerifyServerResult | null;
    }>;
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
    verifySolution(req: Request): Promise<{
        error: string | null;
        payload: import("../types.js").Payload | import("../types.js").ServerSignaturePayload | null;
        verification: import("../types.js").VerifySolutionResult | import("../types.js").VerifyServerResult | null;
    }>;
}
export declare class AltchaMiddleware implements NestMiddleware {
    private readonly altchaService;
    constructor(altchaService: AltchaService);
    use(req: Request, res: Response, next: NextFunction): Promise<void>;
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
