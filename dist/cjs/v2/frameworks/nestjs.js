"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AltchaModule = exports.AltchaMiddleware = exports.AltchaController = exports.AltchaService = exports.Altcha = exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.createAltchaMiddleware = createAltchaMiddleware;
const common_1 = require("@nestjs/common");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const pow_js_1 = require("../pow.js");
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
const ALTCHA_OPTIONS = Symbol('ALTCHA_OPTIONS');
exports.Altcha = (0, common_1.createParamDecorator)((_data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.altcha;
});
function createAltchaMiddleware(options = {}) {
    const { throwOnFailure = true } = options;
    let AltchaMiddleware = class AltchaMiddleware {
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
                throw new common_1.HttpException(error, common_1.HttpStatus.BAD_REQUEST);
            }
            next();
        }
    };
    AltchaMiddleware = __decorate([
        (0, common_1.Injectable)(),
        __metadata("design:paramtypes", [AltchaService])
    ], AltchaMiddleware);
    return AltchaMiddleware;
}
let AltchaService = class AltchaService {
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
            throw new common_1.HttpException('deriveKey and createChallengeParameters are required to generate challenges. Omit the /challenge route when relying on Sentinel to issue challenges.', common_1.HttpStatus.INTERNAL_SERVER_ERROR);
        }
        const challenge = await (0, pow_js_1.createChallenge)({
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
            return req.cookies?.[cookieName];
        }
        return req.body?.[this.fieldName];
    }
    async verify(payload) {
        return (0, shared_js_1.verify)(payload, this.deriveKey, this.hmacSignatureSecret, this.hmacKeySignatureSecret, this.store, this.verifyServerOptions);
    }
};
exports.AltchaService = AltchaService;
exports.AltchaService = AltchaService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(ALTCHA_OPTIONS)),
    __metadata("design:paramtypes", [Object])
], AltchaService);
let AltchaController = class AltchaController {
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
exports.AltchaController = AltchaController;
__decorate([
    (0, common_1.Get)('challenge'),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], AltchaController.prototype, "getChallenge", null);
__decorate([
    (0, common_1.Post)('verify'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AltchaController.prototype, "verifySolution", null);
exports.AltchaController = AltchaController = __decorate([
    (0, common_1.Controller)('altcha'),
    __metadata("design:paramtypes", [AltchaService])
], AltchaController);
let AltchaMiddleware = class AltchaMiddleware {
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
            throw new common_1.HttpException(error, common_1.HttpStatus.BAD_REQUEST);
        }
        next();
    }
};
exports.AltchaMiddleware = AltchaMiddleware;
exports.AltchaMiddleware = AltchaMiddleware = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [AltchaService])
], AltchaMiddleware);
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
exports.AltchaModule = AltchaModule;
exports.AltchaModule = AltchaModule = AltchaModule_1 = __decorate([
    (0, common_1.Module)({})
], AltchaModule);
exports.default = AltchaModule;
