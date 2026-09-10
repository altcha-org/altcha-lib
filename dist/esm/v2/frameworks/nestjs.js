var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var AltchaModule_1;
import { Module, Controller, Get, Post, Req, Header, Injectable, Inject, HttpException, HttpStatus, createParamDecorator, } from '@nestjs/common';
import { randomInt } from '../helpers.js';
import { createChallenge } from '../pow.js';
import { deriveHmacKeySecret, verify } from './shared.js';
import { CappedMap } from '../capped-map.js';
export { CappedMap, deriveHmacKeySecret, randomInt };
const ALTCHA_OPTIONS = Symbol('ALTCHA_OPTIONS');
/**
 * Reads request cookies without assuming a cookie-parser is installed.
 * Prefers a parsed `cookies` object (Express `cookie-parser`, `@fastify/cookie`)
 * and falls back to parsing the raw `Cookie` header otherwise.
 */
function readCookies(req) {
    if (req.cookies && typeof req.cookies === 'object') {
        return req.cookies;
    }
    const header = req.headers?.cookie;
    const raw = Array.isArray(header) ? header.join('; ') : header;
    if (!raw) {
        return {};
    }
    const out = {};
    for (const pair of raw.split(';')) {
        const eq = pair.indexOf('=');
        if (eq === -1) {
            continue;
        }
        const key = pair.slice(0, eq).trim();
        if (!key) {
            continue;
        }
        const value = pair.slice(eq + 1).trim();
        try {
            out[key] = decodeURIComponent(value);
        }
        catch {
            out[key] = value;
        }
    }
    return out;
}
/**
 * Clears the ALTCHA cookie regardless of the underlying HTTP adapter.
 * Falls back to emitting an expiring `Set-Cookie` header when no framework
 * helper is available (e.g. the raw `http.ServerResponse` seen by Fastify
 * middleware).
 */
function clearAltchaCookie(res, name, path = '/') {
    if (!res) {
        return;
    }
    if (typeof res.clearCookie === 'function') {
        res.clearCookie(name, { path: path || '/' });
        return;
    }
    const cookie = `${name}=; Path=${path || '/'}; Max-Age=0`;
    if (typeof res.header === 'function') {
        res.header('Set-Cookie', cookie);
        return;
    }
    if (typeof res.setHeader === 'function') {
        const existing = typeof res.getHeader === 'function'
            ? res.getHeader('Set-Cookie')
            : undefined;
        if (Array.isArray(existing)) {
            res.setHeader('Set-Cookie', [...existing, cookie]);
        }
        else if (typeof existing === 'string' && existing) {
            res.setHeader('Set-Cookie', [existing, cookie]);
        }
        else {
            res.setHeader('Set-Cookie', cookie);
        }
    }
}
export const Altcha = createParamDecorator((_data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.altcha;
});
export function createAltchaMiddleware(options = {}) {
    const { throwOnFailure = true } = options;
    let AltchaMiddleware = class AltchaMiddleware {
        altchaService;
        constructor(altchaService) {
            this.altchaService = altchaService;
        }
        async use(req, res, next) {
            const { error } = await this.altchaService.attachResult(req, res);
            if (error && throwOnFailure) {
                throw new HttpException(error, HttpStatus.BAD_REQUEST);
            }
            next();
        }
    };
    AltchaMiddleware = __decorate([
        Injectable(),
        __param(0, Inject(AltchaService)),
        __metadata("design:paramtypes", [AltchaService])
    ], AltchaMiddleware);
    return AltchaMiddleware;
}
/**
 * Guard variant of the ALTCHA middleware.
 *
 * Prefer this over {@link createAltchaMiddleware} when running on the Fastify
 * adapter: Fastify middleware runs before the body is parsed, so a payload sent
 * in the request body is not visible to middleware. Guards run after body
 * parsing on every adapter, so body- and cookie-delivered payloads both work.
 */
export function createAltchaGuard(options = {}) {
    const { throwOnFailure = true } = options;
    let AltchaGuard = class AltchaGuard {
        altchaService;
        constructor(altchaService) {
            this.altchaService = altchaService;
        }
        async canActivate(context) {
            const http = context.switchToHttp();
            const req = http.getRequest();
            const res = http.getResponse();
            const { error } = await this.altchaService.attachResult(req, res);
            if (error && throwOnFailure) {
                throw new HttpException(error, HttpStatus.BAD_REQUEST);
            }
            return true;
        }
    };
    AltchaGuard = __decorate([
        Injectable(),
        __param(0, Inject(AltchaService)),
        __metadata("design:paramtypes", [AltchaService])
    ], AltchaGuard);
    return AltchaGuard;
}
let AltchaService = class AltchaService {
    hmacSignatureSecret;
    hmacKeySignatureSecret;
    createChallengeParameters;
    deriveKey;
    fieldName;
    setCookieOptions;
    store;
    verifyServerOptions;
    constructor(options) {
        this.hmacSignatureSecret = options.hmacSignatureSecret;
        this.hmacKeySignatureSecret = options.hmacKeySignatureSecret;
        this.createChallengeParameters = options.createChallengeParameters;
        this.deriveKey = options.deriveKey;
        this.fieldName = options.fieldName || 'altcha';
        this.setCookieOptions = options.setCookie;
        this.store = options.store;
        this.verifyServerOptions = options.verifyServer;
    }
    get setCookie() {
        return this.setCookieOptions;
    }
    async getChallenge() {
        const { createChallengeParameters, deriveKey } = this;
        if (!deriveKey || !createChallengeParameters) {
            throw new HttpException('deriveKey and createChallengeParameters are required to generate challenges. Omit the /challenge route when relying on Sentinel to issue challenges.', HttpStatus.INTERNAL_SERVER_ERROR);
        }
        const challenge = await createChallenge({
            deriveKey,
            hmacSignatureSecret: this.hmacSignatureSecret,
            hmacKeySignatureSecret: this.hmacKeySignatureSecret,
            ...createChallengeParameters(),
        });
        return {
            configuration: this.setCookieOptions
                ? { setCookie: this.setCookieOptions }
                : undefined,
            ...challenge,
        };
    }
    getPayloadFromRequest(req, cookieName) {
        if (cookieName) {
            return readCookies(req)[cookieName];
        }
        const value = req.body?.[this.fieldName];
        return typeof value === 'string' ? value : undefined;
    }
    async verify(payload, options = {}) {
        return verify(payload, this.deriveKey, this.hmacSignatureSecret, this.hmacKeySignatureSecret, this.store, options.allowRemote ? this.verifyServerOptions : undefined);
    }
    /**
     * Verifies the payload carried by `req` (body field or configured cookie),
     * stores the outcome on `req.altcha`, and clears the ALTCHA cookie on `res`
     * when a cookie is configured. Shared by the middleware and the guard.
     */
    async attachResult(req, res) {
        const payload = this.getPayloadFromRequest(req, this.setCookie?.name);
        const { error, payload: resultPayload, verification, } = await this.verify(payload, { allowRemote: true });
        const result = {
            error,
            payload: resultPayload,
            verification,
        };
        req.altcha = result;
        if (this.setCookie) {
            clearAltchaCookie(res, this.setCookie.name, this.setCookie.path);
        }
        return result;
    }
};
AltchaService = __decorate([
    Injectable(),
    __param(0, Inject(ALTCHA_OPTIONS)),
    __metadata("design:paramtypes", [Object])
], AltchaService);
export { AltchaService };
let AltchaController = class AltchaController {
    altchaService;
    constructor(altchaService) {
        this.altchaService = altchaService;
    }
    async getChallenge() {
        return this.altchaService.getChallenge();
    }
    async verifySolution(req) {
        const payload = this.altchaService.getPayloadFromRequest(req);
        return this.altchaService.verify(payload);
    }
};
__decorate([
    Get('challenge'),
    Header('Cache-Control', 'no-store'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], AltchaController.prototype, "getChallenge", null);
__decorate([
    Post('verify'),
    __param(0, Req()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AltchaController.prototype, "verifySolution", null);
AltchaController = __decorate([
    Controller('altcha'),
    __param(0, Inject(AltchaService)),
    __metadata("design:paramtypes", [AltchaService])
], AltchaController);
export { AltchaController };
let AltchaMiddleware = class AltchaMiddleware {
    altchaService;
    constructor(altchaService) {
        this.altchaService = altchaService;
    }
    async use(req, res, next) {
        const { error } = await this.altchaService.attachResult(req, res);
        if (error) {
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
        next();
    }
};
AltchaMiddleware = __decorate([
    Injectable(),
    __param(0, Inject(AltchaService)),
    __metadata("design:paramtypes", [AltchaService])
], AltchaMiddleware);
export { AltchaMiddleware };
let AltchaGuard = class AltchaGuard {
    altchaService;
    constructor(altchaService) {
        this.altchaService = altchaService;
    }
    async canActivate(context) {
        const http = context.switchToHttp();
        const req = http.getRequest();
        const res = http.getResponse();
        const { error } = await this.altchaService.attachResult(req, res);
        if (error) {
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
        return true;
    }
};
AltchaGuard = __decorate([
    Injectable(),
    __param(0, Inject(AltchaService)),
    __metadata("design:paramtypes", [AltchaService])
], AltchaGuard);
export { AltchaGuard };
let AltchaModule = AltchaModule_1 = class AltchaModule {
    static register(options) {
        return {
            module: AltchaModule_1,
            controllers: [AltchaController],
            providers: [
                {
                    provide: ALTCHA_OPTIONS,
                    useValue: options,
                },
                AltchaService,
                AltchaMiddleware,
                AltchaGuard,
            ],
            exports: [AltchaService, AltchaMiddleware, AltchaGuard],
        };
    }
    static registerAsync(asyncOptions) {
        return {
            module: AltchaModule_1,
            imports: asyncOptions.imports ?? [],
            controllers: [AltchaController],
            providers: [
                {
                    provide: ALTCHA_OPTIONS,
                    useFactory: asyncOptions.useFactory,
                    inject: asyncOptions.inject ?? [],
                },
                AltchaService,
                AltchaMiddleware,
                AltchaGuard,
            ],
            exports: [AltchaService, AltchaMiddleware, AltchaGuard],
        };
    }
};
AltchaModule = AltchaModule_1 = __decorate([
    Module({})
], AltchaModule);
export { AltchaModule };
export default AltchaModule;
