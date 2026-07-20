# ALTCHA JS Library

ALTCHA TS/JS Library is a lightweight library for creating and verifying [ALTCHA](https://altcha.org) challenges on the server.

## Installation

```sh
npm install altcha-lib
```

## Usage

```ts
import { createChallenge, deriveHmacKeySecret, randomInt, verifySolution } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const HMAC_SECRET = 'your-secret-key';
const HMAC_KEY_SECRET = 'your-other-secret-key';

// On the server: create a challenge and send it to the client
const challenge = await createChallenge({
  algorithm: 'PBKDF2/SHA-256',
  cost: 5_000,
	counter: randomInt(5_000, 10_000),
  deriveKey,
  hmacSignatureSecret: HMAC_SECRET,
	hmacKeySignatureSecret: HMAC_KEY_SECRET,
});

// On the server: verify the solution submitted by the client
const result = await verifySolution({
  challenge: payload.challenge,
  solution: payload.solution,
  deriveKey,
  hmacSignatureSecret: HMAC_SECRET,
	hmacKeySignatureSecret: HMAC_KEY_SECRET,
});

if (result.verified) {
  // challenge passed
}
```

## Get Started

The library includes plugins for several popular frameworks to simplify integration.

- **Express:** [`/docs/express.md`](/docs/express.md)
- **Fastify:** [`/docs/fastify.md`](/docs/fastify.md)
- **Hono:** [`/docs/hono.md`](/docs/hono.md)
- **NestJS:** [`/docs/nestjs.md`](/docs/nestjs.md)
- **Next.js:** [`/docs/nextjs.md`](/docs/nextjs.md)
- **Nuxt:** [`/docs/nuxt.md`](/docs/nuxt.md)
- **SvelteKit:** [`/docs/sveltekit.md`](/docs/sveltekit.md)

If your framework is not listed, see the [Advanced Usage](/docs/advanced-usage.md) guide for custom integrations.

All plugins also support remote verification via ALTCHA Sentinel (`verifyServer` option) — see [`/docs/server-signatures.md`](/docs/server-signatures.md#remote-verification-sentinel-api).

## Documentation

- Advanced Usage: [`/docs/advanced-usage.md`](/docs/advanced-usage.md)
- Algorithms: [`/docs/algorithms.md`](/docs/algorithms.md)
- CLI Usage: [`/docs/cli.md`](/docs/cli.md)
- Configuration Options: [`/docs/configuration-options.md`](/docs/configuration-options.md)
- Obfuscation: [`/docs/obfuscation.md`](/docs/obfuscation.md)
- Store: [`/docs/store.md`](/docs/store.md)
- Usage with ALTCHA Sentinel: [`/docs/server-signatures.md`](/docs/server-signatures.md)
- Using the `/verify` Route: [`/docs/verify-route.md`](/docs/verify-route.md)
- Workers: [`/docs/workers.md`](/docs/workers.md)

## Compatibility

| Runtime           | Version | Notes                                           |
| ----------------- | ------: | ----------------------------------------------- |
| Node.js           |     20+ | Argon2 available natively in 24.7+              |
| Bun               |      1+ | Argon2 not available natively                   |
| Deno              |      2+ | Argon2 not available natively                   |
| WinterCG runtimes |       — | Use WebCrypto [algorithms](/docs/algorithms.md) |

## Run Examples

**Express example (Node.js with `tsx`):**

```sh
npx tsx examples/express-example.ts
```

**Hono example (Bun):**

```sh
bun run --port 3000 examples/hono-example.ts
```

**Hono example (Deno):**

```sh
deno serve --allow-net --sloppy-imports --port 3000 examples/hono-example.ts
```

## Breaking Changes (v2)

Version 2 introduces a new proof-of-work mechanism and challenge format. See the [PoW documentation](https://playground.altcha.org/#/about) for details.

While the overall usage remains similar, the library has been refactored and several function signatures have changed. Using the provided framework plugins is recommended. For unsupported frameworks or custom setups, refer to the [Advanced Usage](/docs/advanced-usage.md) guide.

### Compatibility with v1

The API for the previous PoW version (v1) remains available under the `altcha-lib/v1` path:

```ts
import { createChallenge } from 'altcha-lib/v1';
```

## API Reference

The default import path (`altcha-lib`) uses the v2 API. The v1 API is available at `altcha-lib/v1`.

### v2 (`altcha-lib`)

#### `createChallenge(options: CreateChallengeOptions): Promise<Challenge>`

Creates a new proof-of-work challenge. Generates a random nonce and salt, optionally pre-computes a key prefix from a known counter value, and optionally signs the challenge with HMAC.

| Option | Type | Description |
|---|---|---|
| `algorithm` | `string` | Key derivation algorithm (e.g. `'PBKDF2/SHA-256'`, `'ARGON2ID'`, `'SCRYPT'`). |
| `cost` | `number` | Algorithm-specific cost controlling computational difficulty. |
| `deriveKey` | `DeriveKeyFunction` | Key derivation function. |
| `counter` | `number?` | Known counter value for deterministic mode. |
| `counterMode` | `'uint32' \| 'string'` | Counter encoding format. Defaults to `'uint32'`. |
| `data` | `Record<string, ...>?` | Arbitrary metadata embedded in the challenge. |
| `expiresAt` | `number \| Date?` | Expiry timestamp (seconds) or Date. |
| `hmacAlgorithm` | `HmacAlgorithm?` | HMAC digest algorithm. Defaults to `'SHA-256'`. |
| `hmacKeySignatureSecret` | `string?` | HMAC secret for signing derived keys (deterministic mode). |
| `hmacSignatureSecret` | `string?` | HMAC secret for signing the challenge payload. |
| `keyLength` | `number?` | Derived key length in bytes. Defaults to `32`. |
| `keyPrefix` | `string?` | Required prefix the derived key must match. |
| `keyPrefixLength` | `number?` | Number of bytes used as prefix in deterministic mode. Defaults to `keyLength / 2`. |
| `memoryCost` | `number?` | Memory cost in KiB (Argon2id/scrypt only). |
| `parallelism` | `number?` | Parallelism setting (Argon2id/scrypt only). |

#### `solveChallenge(options: SolveChallengeOptions): Promise<Solution | null>`

Solves a challenge by brute-forcing counter values until the derived key starts with the required prefix. Returns `null` on timeout or abort.

| Option | Type | Description |
|---|---|---|
| `challenge` | `Challenge` | The challenge to solve. |
| `deriveKey` | `DeriveKeyFunction` | Key derivation function. |
| `controller` | `AbortController?` | For cancelling the solve operation. |
| `counterStart` | `number?` | Initial counter value. Defaults to `0`. |
| `counterStep` | `number?` | Increment between attempts. Defaults to `1`. |
| `counterMode` | `'uint32' \| 'string'?` | Counter encoding format. Defaults to `'uint32'`. |
| `timeout` | `number?` | Timeout in milliseconds. Defaults to `90000`. |

#### `solveChallengeWorkers(options): Promise<Solution | null>`

Solves a challenge using multiple Web Workers in parallel. Each worker tests a different interleaved subset of counter values. Automatically retries with fewer workers on out-of-memory errors.

| Option | Type | Description |
|---|---|---|
| `challenge` | `Challenge` | The challenge to solve. |
| `concurrency` | `number` | Number of workers to use (max 16). |
| `createWorker` | `(algorithm: string) => Worker \| Promise<Worker>` | Factory function to create a worker. |
| `controller` | `AbortController?` | For cancelling the solve operation. |
| `counterMode` | `'uint32' \| 'string'?` | Counter encoding format. |
| `onOutOfMemory` | `(concurrency: number) => number \| void?` | Called on OOM; return new concurrency to retry or falsy to abort. |
| `timeout` | `number?` | Timeout in milliseconds. |

#### `verifySolution(options: VerifySolutionOptions): Promise<VerifySolutionResult>`

Verifies a submitted solution against a challenge. Checks expiration, challenge signature integrity, and that the derived key matches the solution.

| Option | Type | Description |
|---|---|---|
| `challenge` | `Challenge` | The original challenge. |
| `solution` | `Solution` | The solution to verify. |
| `hmacSignatureSecret` | `string` | HMAC secret used when the challenge was created. |
| `deriveKey` | `DeriveKeyFunction` | Key derivation function. |
| `counterMode` | `'uint32' \| 'string'?` | Counter encoding format. |
| `hmacAlgorithm` | `HmacAlgorithm?` | HMAC digest algorithm. Defaults to `'SHA-256'`. |
| `hmacKeySignatureSecret` | `string?` | HMAC secret for verifying derived-key signatures. |

Returns `VerifySolutionResult`:

| Field | Type | Description |
|---|---|---|
| `verified` | `boolean` | Whether the solution is valid. |
| `expired` | `boolean` | Whether the challenge has expired. |
| `invalidSignature` | `boolean \| null` | Whether the challenge signature is invalid. |
| `invalidSolution` | `boolean \| null` | Whether the solution is incorrect. |
| `time` | `number` | Time taken to verify in milliseconds. |

#### `verifyFieldsHash(options): Promise<boolean>`

Verifies the SHA hash of specified form fields.

| Option | Type | Description |
|---|---|---|
| `formData` | `FormData \| Record<string, unknown>` | The form data to verify. |
| `fields` | `string[]` | Field names to include in the hash. |
| `fieldsHash` | `string` | The expected hash value. |
| `algorithm` | `string?` | Hash algorithm. Defaults to `'SHA-256'`. |

#### `verifyServerSignature(options): Promise<VerifyServerSignatureResult>`

Verifies a server signature payload from ALTCHA Sentinel.

| Option | Type | Description |
|---|---|---|
| `payload` | `ServerSignaturePayload` | The payload to verify. |
| `hmacSecret` | `string` | The HMAC secret. |

Returns `VerifyServerSignatureResult` (extends `VerifySolutionResult`):

| Field | Type | Description |
|---|---|---|
| `verified` | `boolean` | Whether the signature is valid. |
| `verificationData` | `ServerSignatureVerificationData \| null` | Parsed verification data. |

#### `verifyServer(options: VerifyServerOptions): Promise<VerifyServerResult>`

Verifies a payload remotely by calling ALTCHA Sentinel's `POST /v1/verify/signature` API, instead of verifying the HMAC signature locally.

| Option | Type | Description |
|---|---|---|
| `payload` | `string \| ServerSignaturePayload \| Record<string, unknown>` | The payload to verify, as received from `POST /v1/verify`. |
| `url` | `string` | Full URL of the Sentinel `/v1/verify/signature` endpoint. |
| `secret` | `string?` | API key secret. If provided, Sentinel checks that it matches the API key associated with the payload. |
| `fetch` | `typeof fetch?` | Custom fetch implementation. Defaults to the global `fetch`. |
| `headers` | `Record<string, string>?` | Additional headers to send with the request. |
| `controller` | `AbortController?` | For cancelling the verification request. |
| `timeout` | `number?` | Per-attempt request timeout in milliseconds. Defaults to `10000`. |
| `retries` | `number?` | Number of retry attempts after the first try. Defaults to `0`. |
| `retryDelay` | `number?` | Base delay in milliseconds between retries. Defaults to `300`. |
| `retryBackoff` | `'fixed' \| 'exponential'?` | Backoff strategy for `retryDelay`. Defaults to `'exponential'`. |

Returns `VerifyServerResult`:

| Field | Type | Description |
|---|---|---|
| `verified` | `boolean` | Whether the payload was successfully verified. |
| `apiKey` | `string \| null?` | API key associated with the verification. |
| `reason` | `string?` | Reason or error message if verification failed. |
| `verificationData` | `ServerSignatureVerificationData \| null?` | Verification data returned by Sentinel. |

#### `obfuscate(str: string, options?): Promise<string>`

> Import from `altcha-lib/obfuscation`

Encrypts a string using AES-GCM, with the key derived from a PoW challenge. Returns a base64-encoded payload.

| Option | Type | Description |
|---|---|---|
| `counterMin` | `number?` | Minimum counter value. Defaults to `20`. |
| `counterMax` | `number?` | Maximum counter value. Defaults to `200`. |
| `deriveKey` | `DeriveKeyFunction?` | Key derivation function. Defaults to PBKDF2. |
| `...` | | Any `CreateChallengeOptions` fields. |

#### `deobfuscate(obfuscatedData: string, options?): Promise<string>`

> Import from `altcha-lib/obfuscation`

Decrypts an obfuscated string by solving the embedded PoW challenge and using the derived key.

| Option | Type | Description |
|---|---|---|
| `concurrency` | `number?` | Worker concurrency. Defaults to up to 4. |
| `createWorker` | `(algorithm: string) => Worker?` | Factory to create a worker for solving. |
| `deriveKey` | `DeriveKeyFunction?` | Key derivation function. Defaults to PBKDF2. |

#### `randomInt(max: number, min?: number): number`

Returns a cryptographically random integer between `min` (default `1`) and `max`.

#### `class CappedMap<K, V>`

A `Map` subclass with a fixed maximum size. When full, the oldest entry is evicted on insertion.

```ts
new CappedMap({ maxSize: number })
```

#### `enum HmacAlgorithm`

| Value | String |
|---|---|
| `HmacAlgorithm.SHA_256` | `'SHA-256'` |
| `HmacAlgorithm.SHA_384` | `'SHA-384'` |
| `HmacAlgorithm.SHA_512` | `'SHA-512'` |

---

### v1 (`altcha-lib/v1`)

#### `createChallenge(options: ChallengeOptions): Promise<Challenge>`

Creates a v1 SHA-based proof-of-work challenge.

| Option | Type | Description |
|---|---|---|
| `hmacKey` | `string` | **Required.** HMAC key for signing. |
| `algorithm` | `'SHA-1' \| 'SHA-256' \| 'SHA-512'?` | Hash algorithm. Defaults to `'SHA-256'`. |
| `expires` | `Date?` | Expiry date embedded in the salt. |
| `maxNumber` | `number?` | Maximum random number. Defaults to `1000000`. |
| `number` | `number?` | Fixed number (skips random selection). |
| `params` | `Record<string, string>?` | Extra parameters embedded in the salt. |
| `salt` | `string?` | Custom salt value. |
| `saltLength` | `number?` | Random salt length in bytes. Defaults to `12`. |

#### `verifySolution(payload: string | Payload, hmacKey: string, checkExpires?: boolean): Promise<boolean>`

Verifies a v1 solution payload.

#### `verifyFieldsHash(formData, fields, fieldsHash, algorithm?): Promise<boolean>`

Verifies the hash of specified form fields.

#### `verifyServerSignature(payload: string | ServerSignaturePayload, hmacKey: string): Promise<{ verified: boolean, verificationData: ServerSignatureVerificationData | null }>`

Verifies a v1 server signature.

#### `solveChallenge(challenge, salt, algorithm?, max?, start?): { promise: Promise<Solution | null>, controller: AbortController }`

Solves a v1 challenge by brute force.

#### `solveChallengeWorkers(workerScript, concurrency, challenge, salt, algorithm?, max?, startNumber?): Promise<Solution | null>`

Solves a v1 challenge using Web Workers.

#### `extractParams(payload: string | Payload | Challenge): Record<string, string>`

Extracts URL parameters embedded in a challenge salt.

## License

MIT
