# Store

The `store` tracks used challenges to prevent them from being reused. In distributed environments, use a centralized store such as Redis.

## CappedMap

The library provides a built-in `CappedMap`, an in-memory store that keeps a limited number of entries defined by the `maxSize` option.

**Usage:**

```ts
import { create, CappedMap } from 'altcha-lib/frameworks/hono';

const altcha = create({
  // ...

  store: new CappedMap<string, boolean>({
    maxSize: 1_000,
  }),
});
```

## Custom Store

To implement a custom store, provide an object with `get` and `set` methods:

```ts
interface Store {
  get: (key: string) => Promise<unknown> | unknown;
  set: (key: string, value: boolean) => Promise<unknown> | unknown;
}
```

## Redis

```ts
import { Redis } from 'ioredis';
import { create } from 'altcha-lib/frameworks/hono';

const redis = new Redis();

const altcha = create({
  // ...

  store: {
    get: (key: string) => redis.get(key),
    set: (key: string) => redis.set(key, 1, 'EX', 3_600),
  },
});
```

## Implementation Notes

* **Expiration:** When generating a challenge, use `expiresAt` to limit its validity. The store only needs to retain entries until the challenge expires. With Redis, use the `EX` parameter to set automatic key expiration.
* **Key:** The default challenge identifier is the random `nonce`. A custom identifier can be provided by setting `challengeId` in the `data` field of `createChallenge`.
