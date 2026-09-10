# NestJS

The NestJS plugin simplifies integrating ALTCHA into your application. It provides routes, middleware, and a guard for challenge generation and verification.

Works with both the Express and Fastify adapters. On Fastify, prefer the guard — see [Fastify adapter](#fastify-adapter) below.

## Requirements

Supports NestJS 10, 11 and 12 on both the Express and Fastify adapters.

NestJS 12 ships its core packages as ESM and requires Node.js 20.19+, 22.12+ or newer. CommonJS
applications can still `require()` this integration on those Node versions; nothing in the
integration needs to change when moving from NestJS 11 to 12.

The ALTCHA providers declare their dependencies with explicit `@Inject()` tokens, so they resolve
correctly under builders that do not emit `design:paramtypes` metadata (esbuild, or SWC without
`decoratorMetadata` enabled). Your own controllers and providers still follow whatever NestJS
requires of them.

## Configuration

Register the module synchronously with `AltchaModule.register(options)` or asynchronously with
`AltchaModule.registerAsync({ useFactory, inject, imports })`.

`registerAsync` infers the `useFactory` parameter types from `inject`, so injected providers can be
typed directly on the factory signature:

```ts
AltchaModule.registerAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    hmacSignatureSecret: config.getOrThrow('ALTCHA_HMAC_SIGNATURE_SECRET'),
    createChallengeParameters: () => ({ algorithm: 'PBKDF2/SHA-256', cost: 5_000 }),
    deriveKey,
  }),
});
```

## Routes

* `/challenge` — Generates a new challenge. Configure this endpoint as the widget’s `challenge` URL.
* `/verify` — Optional endpoint for server-side verification. Useful when external services need to verify a payload.

## Middleware

The middleware automatically handles verification during requests.

Features:

* Validates the payload from the request body or a configured cookie.
* Sets `req.altcha: AltchaResult`, which includes the challenge data and verification result.

Options:

* `throwOnFailure: boolean` — Whether to throw an error on verification failure (default: `true`).

```ts
consumer.apply(createAltchaMiddleware()).forRoutes('submit');
```

## Guard

`createAltchaGuard()` performs the same verification as the middleware but runs as a NestJS guard,
so it works identically on the Express and Fastify adapters. It reads the payload from the request
body or the configured cookie, sets `req.altcha: AltchaResult`, and (with `throwOnFailure`, the
default) throws `400 Bad Request` when verification fails.

```ts
import { createAltchaGuard } from 'altcha-lib/frameworks/nestjs';

@Post('submit')
@UseGuards(createAltchaGuard())
submit(@Altcha() altcha: AltchaResult | undefined, @Body() body: Record<string, unknown>) {
  return { altcha, body };
}
```

Options: `throwOnFailure: boolean` (default: `true`), same as the middleware.

## Fastify adapter

NestJS can run on [Fastify](https://docs.nestjs.com/techniques/performance) instead of Express.
Under Fastify, middleware functions receive the **raw** `req`/`res` objects and run *before*
Fastify parses the request body, so a payload sent in the request body is not visible to
`createAltchaMiddleware()`. Use one of the following on Fastify:

* **Guard (recommended)** — `createAltchaGuard()` runs after body parsing, so both body- and
  cookie-delivered payloads are verified and `@Altcha()` works in the handler.
* **Middleware with a cookie** — configure `setCookie` so the payload travels in a cookie. The
  middleware reads it from the `Cookie` header and clears it via `Set-Cookie` (no `cookie-parser`
  required). Note that `req.altcha` set from Fastify middleware is not visible to the `@Altcha()`
  parameter decorator in the handler; read the result from the guard instead.

## Store

The `store` marks challenges as used to prevent reuse.

See [`/docs/store.md`](/docs/store.md) for details.

## Remote verification (Sentinel)

Pass a `verifyServer` option to verify Sentinel-issued payloads remotely via Sentinel's
`/v1/verify/signature` API instead of locally with `hmacSignatureSecret`.

See [`/docs/server-signatures.md#remote-verification-sentinel-api`](/docs/server-signatures.md#remote-verification-sentinel-api) for details.

## Example

* Express adapter (middleware): [`/examples/nestjs-example.ts`](/examples/nestjs-example.ts)
* Fastify adapter (guard): [`/examples/nestjs-fastify-example.ts`](/examples/nestjs-fastify-example.ts)
