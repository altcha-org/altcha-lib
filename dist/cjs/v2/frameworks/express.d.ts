import { Request, Response, NextFunction } from 'express';
import { randomInt } from '../helpers.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
import type { AltchaMiddlewareOptions, AltchaOptions, AltchaResult } from './types.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
export type { AltchaOptions, AltchaResult };
export declare function create(options: AltchaOptions): {
    challengeHandler: (req: Request, res: Response, next: NextFunction) => void;
    verifyHandler: (req: Request, res: Response, next: NextFunction) => void;
    getPayloadFromRequest: (req: Request, cookieName?: string) => Promise<string | undefined>;
    middleware: (options?: AltchaMiddlewareOptions) => (req: Request, res: Response, next: NextFunction) => void;
    verify: typeof verify;
};
declare const _default: {
    CappedMap: typeof CappedMap;
    create: typeof create;
    deriveHmacKeySecret: typeof deriveHmacKeySecret;
    randomInt: typeof randomInt;
};
export default _default;
