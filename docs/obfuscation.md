# Obfuscation

This library provides utilities to obfuscate and deobfuscate data. You can use these features via the CLI (`npx`) or programmatically in your code.

## CLI Usage

### Obfuscate Data

```sh
npx altcha-lib obfuscate [data]
```

### Deobfuscate Data

```sh
npx altcha-lib deobfuscate [data]
```

## Programmatic Usage

```ts
import { obfuscate, deobfuscate } from 'altcha-lib/obfuscation';

const obfuscated = await obfuscate('Hello World');
const original = await deobfuscate(obfuscated);
```
