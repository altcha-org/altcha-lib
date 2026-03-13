# Fastify

The Fastify plugin simplifies integrating ALTCHA into your application. It provides routes and middleware for challenge generation and verification.

## Handlers

* `challengeHandler` — Generates a new challenge. Configure this endpoint as the widget’s `challenge` URL.
* `verifyHandler` — Optional handler for server-side verification. Useful when external services need to verify a payload.

## Middleware

The middleware automatically handles verification during requests.

Features:

* Validates the payload from the request body or a configured cookie.
* Sets `request.altcha: AltchaResult`, which includes the challenge data and verification result.

Options:

* `throwOnFailure: boolean` — Whether to throw an error on verification failure (default: `true`).

## Store

The `store` marks challenges as used to prevent reuse.

See [`/docs/store.md`](/docs/store.md) for details.

## Example

[`/examples/fastify-example.ts`](/examples/fastify-example.ts)

## Usage

### 1. Configure ALTCHA

```ts
import { create, deriveHmacKeySecret, randomInt, CappedMap } from 'altcha-lib/frameworks/fastify';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

// Define your HMAC secret
const HMAC_SECRET = 'secret.key';

const altcha = create({
  // Verification HMAC secrets
  hmacSignatureSecret: HMAC_SECRET,
  hmacKeySignatureSecret: await deriveHmacKeySecret(HMAC_SECRET),

  // Adjust challenge parameters
  createChallengeParameters: () => {
    return {
      algorithm: 'PBKDF2/SHA-256',
      // Adjust cost and counter depending on the algorithm
      cost: 5_000,
      counter: randomInt(5_000, 10_000),
      expiresAt: new Date(Date.now() + 600_000), // 10 minutes
    };
  },

  // Key derivation function for the selected algorithm
  deriveKey,

  // Use a cookie instead of form data to send the payload
  setCookie: {
    name: 'altcha',
    path: '/',
  },

  // In distributed environments, use Redis or another shared store
  store: new CappedMap<string, boolean>({
    maxSize: 1_000,
  }),
});
```

### 2. Mount the challenge routes

```ts
const app = express();

// Mount the /altcha/challenge and /altcha/verify routes
app.get('/altcha/challenge', altcha.challengeHandler);
app.post('/altcha/verify', altcha.verifyHandler);
```

### 3. Protect routes with middleware

```ts
// Apply ALTCHA middleware for automatic verification
app.post(
  '/submit',
  { preHandler: altcha.middleware() },
  async (request, reply) => {
    return reply.send({
      altcha: request.altcha,
      body: request.body,
    });
  }
);
```
