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
  - `number?: number`: Optional number to use. If not provided, a random number will be generated.
  - `salt?: string`: Optional salt string. If not provided, a random salt will be generated.

### `verifySolution(payload, hmacKey)`

Verifies an ALTCHA solution. The payload can be a Base64-encoded JSON payload (as submitted by the widget) or an object.

Parameters:

- `payload: string | Payload`
- `hmacKey: string`

## License

MIT