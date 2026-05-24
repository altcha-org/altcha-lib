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
            const payload = this.altchaService.getPayloadFromRequest(req);
            const { error, payload: resultPayload, verification, } = await this.altchaService.verify(payload);
            req.altcha = {
                error,
                payload: resultPayload,
                verification,
            };
            const setCookie = this.altchaService.setCookie;
            if (setCookie) {
                res.clearCookie(setCookie.name);
            }
            if (error && throwOnFailure) {
                throw new HttpException(error, HttpStatus.BAD_REQUEST);
            }
            next();
        }
    };
    AltchaMiddleware = __decorate([
        Injectable(),
        __metadata("design:paramtypes", [AltchaService])
    ], AltchaMiddleware);
    return AltchaMiddleware;
}
let AltchaService = class AltchaService {
    hmacSignatureSecret;
    hmacKeySignatureSecret;
    createChallengeParameters;
    deriveKey;
    fieldName;
    setCookieOptions;
    store;
    constructor(options) {
        this.hmacSignatureSecret = options.hmacSignatureSecret;
        this.hmacKeySignatureSecret = options.hmacKeySignatureSecret;
        this.createChallengeParameters = options.createChallengeParameters;
        this.deriveKey = options.deriveKey;
        this.fieldName = options.fieldName || 'altcha';
        this.setCookieOptions = options.setCookie;
        this.store = options.store;
    }
    get setCookie() {
        return this.setCookieOptions;
    }
    async getChallenge() {
        const challenge = await createChallenge({
            deriveKey: this.deriveKey,
            hmacSignatureSecret: this.hmacSignatureSecret,
            hmacKeySignatureSecret: this.hmacKeySignatureSecret,
            ...this.createChallengeParameters(),
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
            return req.cookies?.[cookieName];
        }
        return req.body?.[this.fieldName];
    }
    async verify(payload) {
        return verify(payload, this.deriveKey, this.hmacSignatureSecret, this.hmacKeySignatureSecret, this.store);
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
    __metadata("design:paramtypes", [AltchaService])
], AltchaController);
export { AltchaController };
let AltchaMiddleware = class AltchaMiddleware {
    altchaService;
    constructor(altchaService) {
        this.altchaService = altchaService;
    }
    async use(req, res, next) {
        const payload = this.altchaService.getPayloadFromRequest(req, this.altchaService.setCookie?.name);
        const { error, payload: resultPayload, verification, } = await this.altchaService.verify(payload);
        req.altcha = {
            error,
            payload: resultPayload,
            verification,
        };
        const setCookie = this.altchaService.setCookie;
        if (setCookie) {
            res.clearCookie(setCookie.name);
        }
        if (error) {
            throw new HttpException(error, HttpStatus.BAD_REQUEST);
        }
        next();
    }
};
AltchaMiddleware = __decorate([
    Injectable(),
    __metadata("design:paramtypes", [AltchaService])
], AltchaMiddleware);
export { AltchaMiddleware };
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
            ],
            exports: [AltchaService, AltchaMiddleware],
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
            ],
            exports: [AltchaService, AltchaMiddleware],
        };
    }
};
AltchaModule = AltchaModule_1 = __decorate([
    Module({})
], AltchaModule);
export { AltchaModule };
export default AltchaModule;
