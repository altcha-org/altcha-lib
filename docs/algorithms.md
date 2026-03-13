# Algorithms

The package provides implementations of several key-derivation algorithms.

### Node.js (`node:crypto`)

* `altcha-lib/algorithms/pbkdf2`
* `altcha-lib/algorithms/sha`
* `altcha-lib/algorithms/argon2id` *(requires Node.js 24.7+)*
* `altcha-lib/algorithms/scrypt`

### WebCrypto (`crypto.subtle`)

* `altcha-lib/algorithms/web/pbkdf2`
* `altcha-lib/algorithms/web/sha`

## Usage

```ts
import { createChallenge } from 'altcha-lib';
import { deriveKey } from 'altcha-lib/algorithms/pbkdf2';

const challenge = createChallenge({
  // ...

  deriveKey,
});
```

To use Argon2, or any other supported algorithm, import the `deriveKey` function from the algorithm's path:

```ts
import { deriveKey } from 'altcha-lib/algorithms/argon2id';
```

## Custom Algorithms

You can implement a custom `deriveKey` function if a required algorithm is not available in your environment.

### Argon2

If you are using an older Node.js version (< 24.7) where Argon2 is not included in `node:crypto`, you can use a third-party implementation.

#### Example: `@node-rs/argon2`

```ts
import * as argon2 from '@node-rs/argon2';

const deriveKey: DeriveKeyFunction = async (parameters, salt, password) => {
  return {
    parameters: {},
    derivedKey: await argon2.hashRaw(password, {
      algorithm: argon2.Algorithm.Argon2id,
      memoryCost: parameters.memoryCost,
      outputLen: parameters.keyLength,
      parallelism: parameters.parallelism || 1,
      salt,
      timeCost: parameters.cost,
    }),
  };
};
```

#### Example: `hash-wasm`

```ts
import { argon2id } from 'hash-wasm';

const deriveKey: DeriveKeyFunction = async (parameters, salt, password) => {
  return {
    parameters: {},
    derivedKey: await argon2id({
      hashLength: parameters.keyLength,
      iterations: parameters.cost,
      memorySize: parameters.memoryCost,
      outputType: 'binary',
      parallelism: parameters.parallelism || 1,
      password,
      salt,
    }),
  };
};
```
