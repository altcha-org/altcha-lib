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
exports.AltchaModule = exports.AltchaGuard = exports.AltchaMiddleware = exports.AltchaController = exports.AltchaService = exports.Altcha = exports.randomInt = exports.deriveHmacKeySecret = exports.CappedMap = void 0;
exports.createAltchaMiddleware = createAltchaMiddleware;
exports.createAltchaGuard = createAltchaGuard;
const common_1 = require("@nestjs/common");
const helpers_js_1 = require("../helpers.js");
Object.defineProperty(exports, "randomInt", { enumerable: true, get: function () { return helpers_js_1.randomInt; } });
const pow_js_1 = require("../pow.js");
const shared_js_1 = require("./shared.js");
Object.defineProperty(exports, "deriveHmacKeySecret", { enumerable: true, get: function () { return shared_js_1.deriveHmacKeySecret; } });
const capped_map_js_1 = require("../capped-map.js");
Object.defineProperty(exports, "CappedMap", { enumerable: true, get: function () { return capped_map_js_1.CappedMap; } });
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
            const { error } = await this.altchaService.attachResult(req, res);
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
/**
 * Guard variant of the ALTCHA middleware.
 *
 * Prefer this over {@link createAltchaMiddleware} when running on the Fastify
 * adapter: Fastify middleware runs before the body is parsed, so a payload sent
 * in the request body is not visible to middleware. Guards run after body
 * parsing on every adapter, so body- and cookie-delivered payloads both work.
 */
function createAltchaGuard(options = {}) {
    const { throwOnFailure = true } = options;
    let AltchaGuard = class AltchaGuard {
        constructor(altchaService) {
            this.altchaService = altchaService;
        }
        async canActivate(context) {
            const http = context.switchToHttp();
            const req = http.getRequest();
            const res = http.getResponse();
            const { error } = await this.altchaService.attachResult(req, res);
            if (error && throwOnFailure) {
                throw new common_1.HttpException(error, common_1.HttpStatus.BAD_REQUEST);
            }
            return true;
        }
    };
    AltchaGuard = __decorate([
        (0, common_1.Injectable)(),
        __metadata("design:paramtypes", [AltchaService])
    ], AltchaGuard);
    return AltchaGuard;
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
            return readCookies(req)[cookieName];
        }
        const value = req.body?.[this.fieldName];
        return typeof value === 'string' ? value : undefined;
    }
    async verify(payload, options = {}) {
        return (0, shared_js_1.verify)(payload, this.deriveKey, this.hmacSignatureSecret, this.hmacKeySignatureSecret, this.store, options.allowRemote ? this.verifyServerOptions : undefined);
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
        const { error } = await this.altchaService.attachResult(req, res);
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
let AltchaGuard = class AltchaGuard {
    constructor(altchaService) {
        this.altchaService = altchaService;
    }
    async canActivate(context) {
        const http = context.switchToHttp();
        const req = http.getRequest();
        const res = http.getResponse();
        const { error } = await this.altchaService.attachResult(req, res);
        if (error) {
            throw new common_1.HttpException(error, common_1.HttpStatus.BAD_REQUEST);
        }
        return true;
    }
};
exports.AltchaGuard = AltchaGuard;
exports.AltchaGuard = AltchaGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [AltchaService])
], AltchaGuard);
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
exports.AltchaModule = AltchaModule;
exports.AltchaModule = AltchaModule = AltchaModule_1 = __decorate([
    (0, common_1.Module)({})
], AltchaModule);
exports.default = AltchaModule;
