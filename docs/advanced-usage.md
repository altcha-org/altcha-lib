# Advanced Usage

```ts
import { randomInt } from 'node:crypto';
import { createChallenge, solveChallenge, verifySolution } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

// HMAC secret used to sign and verify challenges
const HMAC_SIGNATURE_SECRET = 'secret.key';

// Optional: a separate HMAC secret for signing the derived key.
// Enables faster verification in deterministic mode (HMAC check instead of full key derivation).
const HMAC_KEY_SIGNATURE_SECRET = 'different.secret.key';

// 1. Create a challenge
const challenge = await createChallenge({
  algorithm: 'PBKDF2/SHA-256',
  cost: 5000,
  counter: randomInt(5_000, 10_000), // Deterministic mode; use random integer from selected range
  deriveKey,
  expiresAt: new Date(Date.now() + 600_000), // expires in 10 minutes
  hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
  hmacKeySignatureSecret: HMAC_KEY_SIGNATURE_SECRET,
});

// 2. Solve the challenge (client-side)
const solution = await solveChallenge({
  challenge,
  deriveKey,
});

if (!solution) {
  throw new Error('No solution found for the challenge');
}

// 3. Verify the solution (server-side), the solution is verified when `result.verified === true`
const result = await verifySolution({
  challenge,
  deriveKey,
  solution,
  hmacSignatureSecret: HMAC_SIGNATURE_SECRET,
  hmacKeySignatureSecret: HMAC_KEY_SIGNATURE_SECRET,
});

console.log(result);
// {
//   expired: false,
//   invalidSignature: false,
//   invalidSolution: false,
//   time: 0.8,
//   verified: true,
// }
```