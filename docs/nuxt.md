# Nuxt

The Nuxt plugin simplifies integrating ALTCHA into your application. It provides handlers and middleware for challenge generation and verification.

## Handlers

* `challengeHandler` — Generates a new challenge. Configure this endpoint as the widget’s `challenge` URL.
* `verifyHandler` — Optional handler for server-side verification. Useful when external services need to verify a payload.

## Middleware

The middleware automatically handles verification during requests.

Features:

* Validates the payload from the request body or a configured cookie.
* Sets `event.context.altcha`, which includes the challenge data and verification result.

Options:

* `throwOnFailure: boolean` — Whether to throw an error on verification failure (default: `true`).

## Store

The `store` marks challenges as used to prevent reuse.

See [`/docs/store.md`](/docs/store.md) for details.

## Usage

### 1. Create the altcha instance

File: `server/utils/altcha.ts`

```ts
import { create, deriveHmacKeySecret, randomInt, CappedMap } from 'altcha-lib/frameworks/h3';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

// Define your HMAC secret
const HMAC_SECRET = 'secret.key';

export const altcha = create({
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

### 2. Challenge endpoint

File: `server/altcha/challenge.get.ts`

```ts
import { altcha } from '~/server/utils/altcha';
 
export default altcha.challengeHandler;
```


### 3. Standalone verify endpoint

File: `server/altcha/verify.post.ts `

```ts
import { altcha } from '~/server/utils/altcha';
 
export default altcha.verifyHandler;
```

### 4. Protect routes with middleware

File: `server/middleware/altcha.ts`

```ts
import { altcha } from '~/server/utils/altcha';
 
const altchaMiddleware = altcha.middleware({
  throwOnFailure: true,
});
 
export default defineEventHandler(async (event) => {
  const url = getRequestURL(event);
 
  const protectedPaths = ['/submit'];
  const isProtected = protectedPaths.some((path) => url.pathname.startsWith(path));
 
  if (isProtected && event.method === 'POST') {
    await altchaMiddleware(event);
  }
});
```

### 5. Example protected endpoint

File: `server/submit.post.ts`

```ts
export default defineEventHandler(async (event) => {
  // The middleware has already verified the ALTCHA token.
  // If throwOnFailure is true, invalid requests never reach here.
 
  // Optionally inspect the result:
  const altchaResult = event.context.altcha;
  if (!altchaResult?.verification) {
    throw new HTTPError(403, {
      message: altchaResult?.error || 'Verification failed',
    });
  }
 
  const body = await readBody(event);
 
  return { success: true, message: 'Form submitted successfully' };
});
```