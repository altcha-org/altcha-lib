# ALTCHA JS Library

ALTCHA JS Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges.

## Compatibility

This library utilizes [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto).

- Node.js 16+
- Bun 1+
- Deno 1+
- WinterCG-compatible runtimes
- All modern browsers

## Usage

```ts
import { createChallenge, verifySolution } from 'altcha-lib';

const hmacKey = 'secret hmac key';

// Create a new challenge and send it to the client:
const challenge = await createChallenge({
  hmacKey,
  maxNumber: 100000, // the maximum random number
});

// When submitted, verify the payload:
const ok = await verifySolution(payload, hmacKey);
```

### Usage with Node.js 16

In Node.js version 16, there is no global reference to crypto by default. To use this library, you need to add the following code to your codebase:

```ts
globalThis.crypto = require('node:crypto').webcrypto;
```

Or with `import` syntax:

```ts
import { webcrypto } from 'node:crypto';

globalThis.crypto = webcrypto;
```

## API

### `createChallenge(options)`

Creates a new challenge for ALTCHA.

Parameters:

- `options: ChallengeOptions`:
  - `algorithm?: string`: Algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default: `SHA-256`).
  - `expires?: Date`: Optional `expires` time (as `Date` set into the future date).
  - `hmacKey: string` (required): Signature HMAC key.
  - `maxnumber?: number`: Optional maximum number for the random number generator (defaults to 1,000,000).
  - `number?: number`: Optional number to use. If not provided, a random number will be generated.
  - `params?: Record<string, string>`: Optional parameters to be added to the salt as URL-encoded query string. Use `extractParams()` to read them.
  - `salt?: string`: Optional salt string. If not provided, a random salt will be generated.
  - `saltLength?: number`: Optional maximum lenght of the random salt (in bytes, defaults to 12).

Returns: `Promise<Challenge>`

### `extractParams(payload)`

Extracts optional parameters from the challenge or payload.

Parameters:

- `payload: string | Payload | Challenge`

Returns: `Record<string, string>`

### `verifySolution(payload, hmacKey, checkExpires = true)`

Verifies an ALTCHA solution. The payload can be a Base64-encoded JSON payload (as submitted by the widget) or an object.

Parameters:

- `payload: string | Payload`
- `hmacKey: string`
- `checkExpires: boolean = true`: Whether to perform a check on the optional `expires` parameter. Will return `false` if challenge expired.

Returns: `Promise<boolean>`

### `verifyServerSignature(payload, hmacKey)`

Verifies the server signature returned by the API. The payload can be a Base64-encoded JSON payload or an object.

Parameters:

- `payload: string | ServerSignaturePayload`
- `hmacKey: string`

Returns: `Promise<{ verificationData: ServerSignatureVerificationData | null, verified: boolean }>`

### `verifyFieldsHash(formData, fields, fieldsHash, algorithm?)`

Verifies the hash of form fields returned by the Spam Filter.

Parameters:

- `formData: FormData | Record<string, unknown>`
- `fields: string[]`
- `fieldsHash: string`
- `algorithm: Algorithm = 'SHA-256'`

Returns: `Promise<boolean>`

### `solveChallenge(challenge, salt, algorithm?, max?, start?)`

Finds a solution to the given challenge. 

Parameters:

- `challenge: string` (required): The challenge hash.
- `salt: string` (required): The challenge salt.
- `algorithm?: string`: Optional algorithm (default: `SHA-256`).
- `maxnumber?: string`: Optional `maxnumber` to iterate to (default: 1e6).
- `start?: string`: Optional starting number (default: 0).

Returns: `{ controller: AbortController, promise: Promise<Solution | null> }`

### `solveChallengeWorkers(workerScript, concurrency, challenge, salt, algorithm?, max?, start?)`

Finds a solution to the given challenge with [Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Worker/Worker) running concurrently. 

Parameters:

- `workerScript: string` (required): The path or URL of the worker script.
- `concurrency: number` (required): The concurrency (number of workers).
- `challenge: string` (required): The challenge hash.
- `salt: string` (required): The challenge salt.
- `algorithm?: string`: Optional algorithm (default: `SHA-256`).
- `maxnumber?: string`: Optional `maxnumber` to iterate to (default: 1e6).
- `start?: string`: Optional starting number (default: 0).

Returns: `Promise<Solution | null>`

Usage with `altcha-lib/worker`:

```ts
import { solveChallengeWorkers } from 'altcha-lib';

const solution = await solveChallengeWorkers(
  'altcha-lib/worker', // Worker script URL or path
  8, // Spawn 8 workers
  challenge,
  salt,
);
```

## Benchmarks

```
> solveChallenge()
- n = 1,000...............................        312 ops/s ±2.90%
- n = 10,000..............................         31 ops/s ±1.50%
- n = 50,000..............................          6 ops/s ±0.82%
- n = 100,000.............................          3 ops/s ±0.37%
- n = 500,000.............................          0 ops/s ±0.31%

> solveChallengeWorkers() (8 workers)
- n = 1,000...............................         62 ops/s ±3.99%
- n = 10,000..............................         31 ops/s ±6.83%
- n = 50,000..............................         11 ops/s ±4.00%
- n = 100,000.............................          7 ops/s ±2.32%
- n = 500,000.............................          1 ops/s ±1.89%
```

Run with Bun on MacBook Pro M3-Pro. See [/benchmark](/benchmark/) folder for more details.

## License

MIT