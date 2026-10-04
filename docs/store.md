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

To implement a custom store, provide an object with `get` and `set` methods, and preferably `setIfAbsent`:

```ts
interface Store {
  get: (key: string) => Promise<unknown> | unknown;
  set: (key: string, value: boolean) => Promise<unknown> | unknown;
  // Atomically stores `key` unless it exists; returns `true` if it was added.
  setIfAbsent?: (key: string, value: boolean) => Promise<boolean> | boolean;
}
```

When `setIfAbsent` is implemented, it is used instead of `get` + `set`. Without it, two concurrent submissions of the same payload can both pass, because the check and the write are separate calls. `CappedMap` implements `setIfAbsent`.

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
    setIfAbsent: async (key: string) =>
      (await redis.set(key, 1, 'EX', 3_600, 'NX')) === 'OK',
  },
});
```

## Implementation Notes

* **Expiration:** When generating a challenge, use `expiresAt` to limit its validity. The store only needs to retain entries until the challenge expires. With Redis, use the `EX` parameter to set automatic key expiration.
* **Key:** For self-hosted challenges, the default challenge identifier is the random `nonce`. A custom identifier can be provided by setting `challengeId` in the `data` field of `createChallenge`.
* **Server signatures (Sentinel):** The key is the `id` inside the signed `verificationData`. The unsigned top-level `id` is ignored. A verified payload without a signed `id` is rejected when a store is configured.
* **Order:** An id is recorded only after the payload has been verified. Payloads that fail verification never write to the store, so they cannot fill it, evict used ids from a `CappedMap`, or mark someone else's challenge as used. A challenge whose submission failed can be submitted again.
