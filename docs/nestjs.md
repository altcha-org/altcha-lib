# NestJS

The NestJS plugin simplifies integrating ALTCHA into your application. It provides routes and middleware for challenge generation and verification.

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

## Store

The `store` marks challenges as used to prevent reuse.

See [`/docs/store.md`](/docs/store.md) for details.

## Remote verification (Sentinel)

Pass a `verifyServer` option to verify Sentinel-issued payloads remotely via Sentinel's
`/v1/verify/signature` API instead of locally with `hmacSignatureSecret`.

See [`/docs/server-signatures.md#remote-verification-sentinel-api`](/docs/server-signatures.md#remote-verification-sentinel-api) for details.

## Example

[`/examples/nestjs-example.ts`](/examples/nestjs-example.ts)
