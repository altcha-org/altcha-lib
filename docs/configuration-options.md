# Configuration Options

## Frameworks

The `create()` function exported by the framework plugins accepts the following options:

```ts
interface AltchaOptions {
  /**
   * Returns configuration options passed to `createChallenge`.
   * Must include `algorithm` and `cost`; all other `CreateChallengeOptions` fields are optional.
   */
  createChallengeParameters: () => Pick<
    CreateChallengeOptions,
    'algorithm' | 'cost'
  > &
    Partial<CreateChallengeOptions>;
  /**
   * Algorithm-specific key derivation function used to generate challenge keys.
   */
  deriveKey: DeriveKeyFunction;
  /**
   * Name of the form field that carries the ALTCHA payload.
   * Defaults to `'altcha'` if not specified.
   */
  fieldName?: string;
  /**
   * HMAC secret used to sign and verify challenge signatures.
   */
  hmacSignatureSecret: string;
  /**
   * HMAC secret used to sign keys in deterministic mode.
   */
  hmacKeySignatureSecret?: string;
  /**
   * Cookie configuration for sending the payload via a cookie.
   * The `name` field is required; all other `SetCookieOptions` fields are optional.
   */
  setCookie?: RequireField<SetCookieOptions, 'name'>;
  /**
   * Store implementation for tracking used challenges and preventing replay attacks.
   */
  store?: Store;
}
```

## Advanced Usage

### `createChallenge(options: CreateChallengeOptions)`

```ts
import { createChallenge, randomInt } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const challenge = await createChallenge({
  algorithm: 'PBKDF2/SHA-256',
  cost: 5_000,
  counter: randomInt(5_000, 10_000),
  deriveKey,
  expiresAt: new Date(Date.now() + 600_000), // 10 minutes
  hmacSignatureSecret: 'secret.key',
  hmacKeySignatureSecret: 'another.secret.key'
});
```

```ts
interface CreateChallengeOptions {
  /**
   * Key derivation algorithm used for the challenge.
   * Common values: `'PBKDF2/SHA-256'`, `'ARGON2ID'`, `'SCRYPT'`.
   */
  algorithm: string;
  /**
   * Randomly selected integer used as the starting counter in deterministic mode.
   */
  counter?: number;
  /**
   * Encoding format for the counter value.
   * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
   */
  counterMode?: 'uint32' | 'string';
  /**
   * Algorithm-specific cost parameter controlling computational difficulty
   * (e.g., iteration count for PBKDF2, time cost for Argon2id).
   */
  cost: number;
  /**
   * Arbitrary key-value metadata embedded in the challenge.
   */
  data?: Record<string, string | number | boolean | null>;
  /**
   * Algorithm-specific key derivation function used to generate challenge keys.
   */
  deriveKey: DeriveKeyFunction;
  /**
   * Timestamp in seconds or Date after which the challenge is no longer valid.
   */
  expiresAt?: number | Date;
  /**
   * HMAC digest algorithm used for signing challenges.
   * Defaults to `'SHA-256'`.
   */
  hmacAlgorithm?: HmacAlgorithm;
  /**
   * HMAC secret used to sign derived keys in deterministic mode.
   */
  hmacKeySignatureSecret?: string;
  /**
   * HMAC secret used to sign the challenge payload.
   */
  hmacSignatureSecret?: string;
  /**
   * Length of the derived key in bytes.
   * Defaults to `32`.
   */
  keyLength?: number;
  /**
   * Required prefix that the derived key must match for the challenge to be solved.
   */
  keyPrefix?: string;
  /**
   * Number of bytes from the derived key used as the prefix in deterministic mode.
   * Defaults to `keyLength / 2`.
   */
  keyPrefixLength?: number;
  /**
   * Algorithm-specific memory cost in KiB (applicable to Argon2id and scrypt).
   */
  memoryCost?: number;
  /**
   * Algorithm-specific parallelism setting controlling the parallelism
   * (applicable to Argon2id and scrypt).
   */
  parallelism?: number;
}
```

### `solveChallenge(options: SolveChallengeOptions)`

```ts
import { solveChallenge } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const solution = await solveChallenge({
  challenge,
  deriveKey,
});
```

```ts
interface SolveChallengeOptions {
  /**
   * Challenge object to solve, either decoded from a server payload
   * or as originally returned by `createChallenge`.
   */
  challenge: Challenge;
  /**
   * AbortController for cancelling the solve operation before completion.
   */
  controller?: AbortController;
  /**
   * Initial counter value to begin iterating from.
   * Useful for resuming or partitioning work across multiple solvers.
   */
  counterStart?: number;
  /**
   * Increment between counter attempts.
   * Defaults to `1`.
   */
  counterStep?: number;
  /**
   * Encoding format for the counter value.
   * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
   */
  counterMode?: 'uint32' | 'string';
  /**
   * Algorithm-specific key derivation function used to compute candidate keys
   * for each counter value until a match is found.
   */
  deriveKey: DeriveKeyFunction;
  /**
   * Maximum time in milliseconds before the solve attempt is aborted.
   * Defaults to `90_000` (90 seconds).
   */
  timeout?: number;
}
```

### `verifySolution(options: VerifySolutionOptions)`

```ts
import { verifySolution } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const verification = await verifySolution({
  challenge,
  deriveKey,
  solution,
  hmacSignatureSecret: 'secret.key',
  hmacKeySignatureSecret: 'another.secret.key'
});
```

```ts
interface VerifySolutionOptions {
  /**
   * Challenge object to verify against, either decoded from the client payload
   * or as originally returned by `createChallenge`.
   */
  challenge: Challenge;
  /**
   * Encoding format for the counter value.
   * V2 uses `'uint32'`; `'string'` is supported for backward compatibility with V1.
   */
  counterMode?: 'uint32' | 'string';
  /**
   * Algorithm-specific key derivation function used to recompute the expected key
   * during verification.
   */
  deriveKey: DeriveKeyFunction;
  /**
   * HMAC digest algorithm used when verifying challenge signatures.
   * Defaults to `'SHA-256'`.
   */
  hmacAlgorithm?: HmacAlgorithm;
  /**
   * HMAC secret used to verify derived-key signatures in deterministic mode.
   */
  hmacKeySignatureSecret?: string;
  /**
   * HMAC secret used to verify the challenge payload signature.
   */
  hmacSignatureSecret: string;
  /**
   * Solution object to validate, either decoded from the client payload
   * or as returned by `solveChallenge`.
   */
  solution: Solution;
}
```