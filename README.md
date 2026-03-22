# ALTCHA JS Library

ALTCHA TS/JS Library is a lightweight library for creating and verifying [ALTCHA](https://altcha.org) challenges on the server.

## Get Started

The library includes plugins for several popular frameworks to simplify integration.

- **Express:** [`/docs/express.md`](/docs/express.md)
- **Fastify:** [`/docs/fastify.md`](/docs/fastify.md)
- **Hono:** [`/docs/hono.md`](/docs/hono.md)
- **NestJS:** [`/docs/nestjs.md`](/docs/nestjs.md)
- **Next.js:** [`/docs/nextjs.md`](/docs/nextjs.md)
- **Nuxt:** [`/docs/nuxt.md`](/docs/nuxt.md)
- **SvelteKit:** [`/docs/sveltekit.md`](/docs/sveltekit.md)

If your framework is not listed, see the [Advanced Usage](/docs/advanced-usage.md) guide for custom integrations.

## Documentation

- Advanced Usage: [`/docs/advanced-usage.md`](/docs/advanced-usage.md)
- Algorithms: [`/docs/algorithms.md`](/docs/algorithms.md)
- Configuration Options: [`/docs/configuration-options.md`](/docs/configuration-options.md)
- Obfuscation: [`/docs/obfuscation.md`](/docs/obfuscation.md)
- Store: [`/docs/store.md`](/docs/store.md)
- Usage with ALTCHA Sentinel: [`/docs/server-signatures.md`](/docs/server-signatures.md)
- Using the `/verify` Route: [`/docs/verify-route.md`](/docs/verify-route.md)
- Workers: [`/docs/workers.md`](/docs/workers.md)

## Compatibility

| Runtime           | Version | Notes                                           |
| ----------------- | ------: | ----------------------------------------------- |
| Node.js           |     20+ | Argon2 available natively in 24.7+              |
| Bun               |      1+ | Argon2 not available natively                   |
| Deno              |      2+ | Argon2 not available natively                   |
| WinterCG runtimes |       — | Use WebCrypto [algorithms](/docs/algorithms.md) |

### Run examples

**Express example (Node.js with `tsx`):**

```sh
npx tsx examples/express-example.ts
```

**Hono example (Bun):**

```sh
bun run --port 3000 examples/hono-example.ts
```

**Hono example (Deno):**

```sh
deno serve --allow-net --sloppy-imports --port 3000 examples/hono-example.ts
```

## Breaking Changes (v2)

Version 2 introduces a new proof-of-work mechanism and challenge format. See the [PoW documentation](https://playground.altcha.org/#/about) for details.

While the overall usage remains similar, the library has been refactored and several function signatures have changed. Using the provided framework plugins is recommended. For unsupported frameworks or custom setups, refer to the [Advanced Usage](/docs/advanced-usage.md) guide.

### Compatibility with v1

The API for the previous PoW version (v1) remains available under the `altcha-lib/v1` path:

```ts
import { createChallenge } from 'altcha-lib/v1';
```

## License

MIT
