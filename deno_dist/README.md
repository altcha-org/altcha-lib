# ALTCHA JS Library

ALTCHA JS Library is a lightweight, zero-dependency library designed for creating and verifying [ALTCHA](https://altcha.org) challenges specifically tailored for Node.js, Bun, and Deno environments.

## Compatibility

This library utilizes [Web Crypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) and is intended for server-side use.

- Node.js 16+
- Bun 1+
- Deno 1+

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

## API

### `createChallenge(options)`

Creates a new challenge for ALTCHA.

Parameters:

- `options: ChallengeOptions`:
  - `algorithm?: string`: Algorithm to use (`SHA-1`, `SHA-256`, `SHA-512`, default: `SHA-256`).
  - `hmacKey: string` (required): Signature HMAC key.
  - `maxNumber?: number` Optional maximum number for the random number generator (defaults to 1,000,000).
  - `number?: number`: Optional number to use. If not provided, a random number will be generated.
  - `salt?: string`: Optional salt string. If not provided, a random salt will be generated.
  - `saltLength?: number` Optional maximum lenght of the random salt (in bytes, defaults to 12).

Returns: `Promise<Challenge>`

### `verifySolution(payload, hmacKey)`

Verifies an ALTCHA solution. The payload can be a Base64-encoded JSON payload (as submitted by the widget) or an object.

Parameters:

- `payload: string | Payload`
- `hmacKey: string`

Returns: `Promise<boolean>`

### `solveChallenge(challenge, salt, algorithm?, max?, start?)`

Finds a solution to the given challenge. 

Parameters:

- `challenge: string` (required): The challenge hash.
- `salt: string` (required): The challenge salt.
- `algorithm?: string`: Optional algorithm (default: `SHA-256`).
- `max?: string`: Optional `maxnumber` to iterate to (default: 1e6).
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
- `max?: string`: Optional `maxnumber` to iterate to (default: 1e6).
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
- n = 1,000...............................        317 ops/s ±2.63%
- n = 10,000..............................         32 ops/s ±1.88%
- n = 100,000.............................          3 ops/s ±0.34%
- n = 500,000.............................          0 ops/s ±0.32%

> solveChallengeWorkers() (8 workers)
- n = 1,000...............................         66 ops/s ±3.44%
- n = 10,000..............................         31 ops/s ±4.28%
- n = 100,000.............................          7 ops/s ±4.40%
- n = 500,000.............................          1 ops/s ±2.49%
```

Run with Bun on MacBook Pro M3-Pro. See [/benchmark](/benchmark/) folder for more details.

## License

MIT