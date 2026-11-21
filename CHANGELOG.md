# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.10.0] - 2026-11-21

### Security

- v1 `verifySolution` returns `false` when `number` is not an integer. Before, a string `number` could carry the tail of the signed salt across the `&` delimiter: the challenge and signature still matched, but the expiry check and `extractParams` only saw the shortened salt. This let an expired challenge created with `params` and `expires` verify, and hid trailing signed params. v1 `createChallenge` throws for a non-integer `number`.

## [2.9.0] - 2026-11-17

### Added

- `verifyServer` supports Sentinel v2's `POST /v2/verify/signature`. A new `apiKey: { id, secret }` option (a restricted or full key) is sent as `Authorization: Basic base64(id:secret)`.
- `verifyServerSignature` accepts the base64-encoded JSON string payload (`payload: string | ServerSignaturePayload`), decoded the same way the framework plugins decode it.

### Changed

- `verifyServer` sends only `{ payload }` in the request body when `apiKey` is set. `secret` is for a v1 Sentinel only, and Sentinel v2 rejects it on `/v2`.
- `verifyServer` does not retry 4xx responses. An error response's `reason` is the `code` from Sentinel's error body (`{ code, error, statusCode }`), falling back to `error`, then `HTTP_<status>`.
- `verifyServer` flattens Sentinel v2's nested `verificationData` (`{ device: { browser } }`) to the keys `verifyServerSignature` returns (`data['device.browser']`). Local and remote results now have the same shape.
- `verifyServerSignature` returns `verified: false` with `invalidSolution: true` for an undecodable payload or a missing `algorithm`, instead of throwing. An unsupported `algorithm` still throws.
- Docs show remote verification against both Sentinel v2 (`/v2/verify/signature` with `apiKey`) and Sentinel v1 (`/v1/verify/signature` with the optional `secret`), in the README, `docs/server-signatures.md` and every framework guide. The README states that the default export provides the v2 `verifyServerSignature({ payload, hmacSecret })` form, and that the v1 `(payload, hmacKey)` form comes from `altcha-lib/v1`.

## [2.8.0] - 2026-10-24

### Fixed

- Nuxt 4 support: `altcha-lib/frameworks/h3` works with h3 v1 (Nuxt 4, Nitro 2) as well as h3 v2 (Nitro 3), and the `h3` peer dependency accepts `^1.15.0 || ^2.0.0` ([#22](https://github.com/altcha-org/altcha-lib/issues/22)). The plugin no longer imports `h3` at runtime, so it no longer fails with `event.req.headers.get is not a function` when the package manager installs h3 v2 for `altcha-lib` next to Nuxt's h3 v1.
- `altcha-lib/frameworks/h3` middleware leaves the request body readable for later handlers on both h3 majors.
- `altcha-lib/frameworks/h3` errors (403 on failed verification, 400 on an invalid JSON or form data body) are recognized as HTTP errors by both h3 v1 and v2. h3 v1 previously treated them as unhandled errors.
- `docs/nuxt.md`: route files live under `server/routes/`, imports use `~~/server/...` (Nuxt 4's `~` points to `app/`), and the example uses `createError`, which exists in h3 v1 and v2.

### Changed

- The build uses TypeScript 6. `tsconfig.cjs.json` sets `ignoreDeprecations: "6.0"` to keep `moduleResolution: "node"` for the CommonJS build, which TypeScript 6 deprecates and TypeScript 7 removes.

## [2.7.0] - 2026-10-21

### Fixed

- SvelteKit 3 support: the `@sveltejs/kit` peer dependency accepts `^2.0.0 || ^3.0.0`, so npm no longer fails with `ERESOLVE` in SvelteKit 3 projects ([#21](https://github.com/altcha-org/altcha-lib/issues/21)). `altcha-lib/frameworks/sveltekit` no longer imports `Handle` from `@sveltejs/kit`, which SvelteKit 3 moved to `@sveltejs/kit/hooks`.

### Changed

- `altcha-lib/frameworks/sveltekit` is ESM-only, like `@sveltejs/kit`. The CommonJS build could not be loaded because `@sveltejs/kit` cannot be `require()`d; `require('altcha-lib/frameworks/sveltekit')` now fails with `ERR_PACKAGE_PATH_NOT_EXPORTED` for `altcha-lib` instead.
- `altcha-lib/frameworks/sveltekit` responds with `Response.json` instead of SvelteKit's `json` helper, which SvelteKit 3 deprecates.

## [2.6.0] - 2026-10-05

### Security

- `createChallenge` no longer publishes the whole derived key when `keyPrefixLength` is at least the key length. Before, a challenge with `hmacKeySignatureSecret` could be verified without any work by submitting the published `keyPrefix` as the solution.
- `obfuscate()` no longer exposes its AES key when `keyPrefixLength` is passed in its options.
- `createChallenge` no longer creates challenges with an empty `keyPrefix` (for example with `keyLength: 1`, `keyPrefixLength: 0` or `keyPrefix: ''`), which any counter solved.
- Framework plugins: replay protection for server-signed (Sentinel) payloads uses the `id` inside the signed `verificationData` instead of the unsigned top-level `id`, which could be changed or removed to replay a payload.
- Framework plugins: payload ids are recorded in the replay store only after the payload has been verified. Unverified payloads could fill the store, evict used ids from a `CappedMap` (allowing replays), or mark another user's challenge as used.
- `verifyServerSignature` validates `payload.algorithm` (not covered by the signature) before use. It accepts only `SHA-1`, `SHA-256`, `SHA-384` and `SHA-512`.
- A `__proto__` key in challenge parameters is now covered by the signature. Before, it was dropped from the signed JSON, so it could be injected into a signed challenge.

### Fixed

- The browser SHA key derivation (`altcha-lib/algorithms/web/sha`) produces the same keys as the Node version. They differed for SHA-384 and SHA-512 with the default `keyLength` 32 and `cost` > 1, and for any `keyLength` below the digest size.
- The browser PBKDF2 key derivation (`altcha-lib/algorithms/web/pbkdf2`) supports any `keyLength`, not only 16, 24 and 32.
- `verifySolution` returns `invalidSolution` instead of throwing for a malformed solution: a `derivedKey` that is missing or not lowercase hex, or a missing `solution`. Both verification paths now reject an uppercase `derivedKey` (the key-signature path used to accept it).
- `verifySolution` returns `invalidSolution` for a counter that is not an exact integer in range. Before, `"42"` and `2 ** 32 + 42` verified as `42`.
- `solveChallenge` throws immediately for an invalid `keyPrefix` instead of searching until the timeout.
- An odd-length uppercase `keyPrefix` (for example from another library) can be solved and verified.
- `verifyServerSignature` returns `invalidSignature` instead of throwing when `payload.signature` is missing.
- `verifyServerSignature` treats a payload as expired as soon as the current time passes `expire`, the same as `verifySolution`. Before, it allowed up to 1 second of grace.
- CLI: `create --algorithm` is case-insensitive and rejects unsupported names. Before, a lowercase name created a challenge that `solve` could not solve.
- CLI: `create` defaults to `PBKDF2/SHA-256`, as documented. It used `SHA-256`.

### Added

- `Store.setIfAbsent(key, value)`: optional atomic check-and-set. When a store implements it, the framework plugins use it, so only one of two concurrent submissions of the same payload passes. `CappedMap` implements it; `docs/store.md` shows a Redis implementation with `SET … NX`.
- `docs/advanced-usage.md` documents the challenge signature format (canonical JSON) for other implementations.
- `docs/server-signatures.md` documents the expiry rules and how to check `fieldsHash` with `verifyFieldsHash`.

### Changed

- **BREAKING:** `createChallenge` validates its options and throws for invalid values:
  - `keyPrefixLength` must be a positive integer smaller than the derived key length. Values above half the derived key are capped at half. The default is `floor(keyLength / 2)`. With SHA-256 and `keyLength: 64`, the default now throws in counter mode, because the derived key is only 32 bytes.
  - `keyPrefix` must be a non-empty hex string no longer than the key. It is lowercased before signing.
  - `counter` must be an integer from 0 to 2^32 - 1 (`'uint32'`) or `Number.MAX_SAFE_INTEGER` (`'string'`).
  - `cost` and `keyLength` must be positive integers, and so must `memoryCost` and `parallelism` when set.
  - `counterMode` must be `'uint32'` or `'string'`.
  - `expiresAt` must be a valid `Date` or a positive number of seconds.
  - `hmacAlgorithm` must be `SHA-256`, `SHA-384` or `SHA-512`.
- **BREAKING:** HMAC secrets must be non-empty strings:
  - `createChallenge` throws for an empty or `null` `hmacSignatureSecret`, and for `hmacKeySignatureSecret` without `hmacSignatureSecret` (it used to be ignored). Omitting `hmacSignatureSecret` still creates an unsigned challenge.
  - `verifySolution` throws for a missing or empty `hmacSignatureSecret`.
  - `verifyServerSignature` throws for a missing or empty `hmacSecret`.
- **BREAKING:** The built-in `deriveKey` functions accept only their exact algorithm names and throw otherwise: `SHA-256`, `SHA-384`, `SHA-512`; `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`; `SCRYPT`; `ARGON2ID`. The Node functions used to fall back to SHA-256 for unknown names, and scrypt and Argon2id ignored the name. The scrypt and Argon2id functions require `memoryCost`.
- **BREAKING:** `verifySolution` and `verifyServerSignature` throw for an unsupported `hmacAlgorithm` or `payload.algorithm`. The framework plugins return the error as a failed verification.
- **BREAKING:** Framework `challengeHandler`s fail with a configuration error when `hmacSignatureSecret` is not set, instead of issuing unsigned challenges that their own `verify` rejects.
- **BREAKING:** With a replay store configured, server-signed payloads without an `id` in `verificationData` are rejected. Sentinel always includes it.
- Framework plugins: a self-hosted challenge whose submission failed verification can be submitted again; it is no longer marked as used.

## [2.5.0] - 2026-09-10

### Added

- Support for Nest.js v12.

## [2.4.0] - 2026-08-30

### Fixed

- Nest.js with Fastify ([#18](https://github.com/altcha-org/altcha-lib/issues/18)).
- Nest.js `registerAsync` typing ([#19](https://github.com/altcha-org/altcha-lib/issues/19)).

## [2.3.2] - 2026-07-27

### Fixed

- Enforce `keyPrefix` in PoW v2 fallback verification.

## [2.3.1] - 2026-07-20

### Fixed

- `verifyHandler` (the standalone `/verify` endpoint, meant for custom or external integrations) called `verifyServer` when a `verifyServer` option was configured.

## [2.3.0] - 2026-07-20

### Added

- `verifyServer()` verifies a payload remotely through ALTCHA Sentinel's `POST /v1/verify/signature` API instead of checking the HMAC signature locally. It supports timeouts, retries with fixed or exponential backoff, a custom `fetch`, and aborting through an `AbortController`.
- All framework plugins (Express, Fastify, NestJS, Next.js, Nuxt/H3, SvelteKit, Hono) accept a `verifyServer` option. When it is set, Sentinel-issued payloads are verified remotely through the existing `verifyHandler` and middleware.

### Changed

- `hmacSignatureSecret`, `deriveKey` and `createChallengeParameters` are optional in the framework plugin options, so a Sentinel-only setup can be `create({ verifyServer: { url, secret } })`. Calling `challengeHandler` without `deriveKey` or `createChallengeParameters` fails with a configuration error.

## [2.2.0] - 2026-05-24

### Fixed

- Framework plugins send a default `Cache-Control: no-store` header ([#17](https://github.com/altcha-org/altcha-lib/issues/17)).

## [2.1.0] - 2026-05-20

### Fixed

- Fastify and Express throw an error when `throwOnFailure` is set ([#16](https://github.com/altcha-org/altcha-lib/issues/16)).

## [2.0.1] - 2026-04-10

### Added

- CLI utility.

### Fixed

- `solveChallenge` yielding and abort.

## [2.0.0] - 2026-04-07

### Changed

- **BREAKING:** New proof-of-work mechanism (v2). See the [documentation](https://altcha.org/docs/v2/widget-v3/).

## [2.0.0-beta.1] - 2026-03-13

### Added

- Beta release of the PoW v2 mechanism.

## [1.4.1] - 2025-12-13

### Fixed

- Use `&` instead of `;` as the salt delimiter. This keeps salt parameters extractable by previous versions of the libraries while still preventing the salt parameter splicing attack.

## [1.4.0] - 2025-12-11

### Security

- Fixed a parameter splicing vulnerability in salt handling that enabled replay attacks.

## [1.3.0] - 2025-06-07

### Changed

- Updated typings for the server verification payload with Sentinel.

### Fixed

- Deno 2.x TypeScript and test compatibility.
- Vulnerable development dependencies (Vitest).

## [1.2.0] - 2024-12-21

### Fixed

- `solveChallengeWorkers` algorithm ([#13](https://github.com/altcha-org/altcha-lib/issues/13)).

## [1.1.1] - 2024-11-14

### Fixed

- Concurrency limit ([#11](https://github.com/altcha-org/altcha-lib/issues/11)).

## [1.1.0] - 2024-09-11

### Changed

- Reverted the `expires` format and presence check added in 1.0.0, because it could cause unexpected verification results. The check is not needed for security, since `expires` is signed.

## [1.0.0] - 2024-09-02

First stable release, freezing the API for version 1.x.

### Fixed

- `expires` verification checks for the presence and format of the parameter.
- More tests and docs.

## [0.5.1] - 2024-07-25

### Fixed

- `extractParams` no longer throws for invalid input.

## [0.5.0] - 2024-07-24

### Added

- `verifyFieldsHash` to verify the fields signature when using the Spam Filter.
- JSDoc for functions.

### Fixed

- `ServerSignatureVerificationData` types.
- `verifySolution` and `verifyServerSignature` no longer throw when the payload is not a valid base64 string.

## [0.4.1] - 2024-07-19

### Changed

- The `concurrency` option is capped at the maximum value instead of throwing an error.

## [0.4.0] - 2024-07-12

### Removed

- The automatic `crypto` global reference for Node 16 (see [Usage with Node.js 16](https://github.com/altcha-org/altcha-lib?tab=readme-ov-file#usage-with-nodejs-16)).

## [0.3.0] - 2024-05-12

### Added

- The `salt` includes custom parameters as a URL-encoded query string, allowing custom data and an expiration time in a standardized format.
- `createChallenge` accepts `expires: Date`, which appends an `?expires=` parameter (a Unix timestamp in seconds) to the salt.
- `verifySolution` checks the expiration automatically when the salt contains `?expires=`. Pass `checkExpires: false` as the optional third argument to disable it.
- `extractParams` extracts custom parameters from the base64-encoded payload, the payload object or the challenge object.

[2.10.0]: https://github.com/altcha-org/altcha-lib/compare/v2.9.0...v2.10.0
[2.9.0]: https://github.com/altcha-org/altcha-lib/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/altcha-org/altcha-lib/compare/v2.7.0...v2.8.0
[2.7.0]: https://github.com/altcha-org/altcha-lib/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/altcha-org/altcha-lib/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/altcha-org/altcha-lib/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/altcha-org/altcha-lib/compare/v2.3.2...v2.4.0
[2.3.2]: https://github.com/altcha-org/altcha-lib/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/altcha-org/altcha-lib/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/altcha-org/altcha-lib/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/altcha-org/altcha-lib/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/altcha-org/altcha-lib/compare/v2.0.3...v2.1.0
[2.0.1]: https://github.com/altcha-org/altcha-lib/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/altcha-org/altcha-lib/compare/v2.0.0-beta.2...v2.0.0
[2.0.0-beta.1]: https://github.com/altcha-org/altcha-lib/compare/1.4.1...v2.0.0-beta.1
[1.4.1]: https://github.com/altcha-org/altcha-lib/compare/1.4.0...1.4.1
[1.4.0]: https://github.com/altcha-org/altcha-lib/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/altcha-org/altcha-lib/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/altcha-org/altcha-lib/compare/1.1.1...1.2.0
[1.1.1]: https://github.com/altcha-org/altcha-lib/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/altcha-org/altcha-lib/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/altcha-org/altcha-lib/compare/0.5.1...1.0.0
[0.5.1]: https://github.com/altcha-org/altcha-lib/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/altcha-org/altcha-lib/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/altcha-org/altcha-lib/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/altcha-org/altcha-lib/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/altcha-org/altcha-lib/compare/0.2.0...0.3.0
