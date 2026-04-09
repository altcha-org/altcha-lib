# CLI

The `altcha-lib` package includes a command-line interface for creating, solving, and verifying challenges, as well as obfuscating data.

## Installation

```sh
npm install -g altcha-lib
```

Or run without installing using `npx`:

```sh
npx altcha-lib <command> [options]
```

## Commands

### `create`

Creates a new challenge and prints it as JSON.

```sh
altcha-lib create [options]
```

**Options:**

| Option | Description | Default |
|---|---|---|
| `--algorithm <algo>` | Key derivation algorithm | `PBKDF2/SHA-256` |
| `--cost <n>` | Algorithm cost parameter | `5000` (SHA/PBKDF2), `16384` (SCRYPT), `3` (ARGON2ID) |
| `--hmac-secret <secret>` | HMAC secret for signing the challenge | — |
| `--hmac-key-secret <secret>` | HMAC secret for signing the derived key (deterministic mode) | — |
| `--counter <n>` | Known counter value for deterministic mode | — |
| `--expires <seconds>` | Seconds from now until the challenge expires | — |
| `--key-prefix <prefix>` | Key prefix override | — |
| `--memory-cost <n>` | Memory cost in KiB (SCRYPT / ARGON2ID only) | — |
| `--parallelism <n>` | Parallelism factor (SCRYPT / ARGON2ID only) | — |

**Supported algorithms:** `PBKDF2/SHA-256`, `PBKDF2/SHA-384`, `PBKDF2/SHA-512`, `SCRYPT`, `ARGON2ID`, `SHA-256`, `SHA-384`, `SHA-512`

**Examples:**

```sh
# Unsigned challenge
altcha-lib create --algorithm PBKDF2/SHA-256 --cost 5000

# Signed challenge, expires in 5 minutes
altcha-lib create --algorithm PBKDF2/SHA-256 --cost 5000 \
  --hmac-secret mysecret \
  --expires 300

# Deterministic challenge (known solution)
altcha-lib create --algorithm SHA-256 --cost 5000 \
  --hmac-secret mysecret \
  --hmac-key-secret mykeysecret \
  --counter 42
```

---

### `solve`

Solves a challenge using multiple worker threads and prints the solution as JSON. The input can be a file path, an inline JSON string, or a JSON challenge piped via stdin.

```sh
altcha-lib solve [challenge] [options]
```

**Options:**

| Option | Description | Default |
|---|---|---|
| `--workers <n>` | Number of worker threads | `1` |

**Examples:**

```sh
# Solve from a file
altcha-lib solve challenge.json

# Solve with multiple workers
altcha-lib solve challenge.json --workers 4

# Pipe from create
altcha-lib create --algorithm SHA-256 --cost 5000 --hmac-secret s | altcha-lib solve
```

---

### `verify`

Verifies a solution against a challenge and prints the result as JSON. Exits with code `0` on success, `1` on failure.

```sh
altcha-lib verify [challenge] [solution] [options]
altcha-lib verify [payload] [options]
```

Accepts two separate inputs (challenge and solution) or a single combined payload `{ challenge, solution }`. Each input can be a file path, an inline JSON string, or piped via stdin.

**Options:**

| Option | Description | Default |
|---|---|---|
| `--hmac-secret <secret>` | HMAC secret used when creating the challenge | **required** |
| `--hmac-key-secret <secret>` | HMAC key secret used when creating the challenge (deterministic mode) | — |

**Examples:**

```sh
# Verify using separate files
altcha-lib verify challenge.json solution.json --hmac-secret mysecret

# Verify a combined payload file
altcha-lib verify payload.json --hmac-secret mysecret

# Deterministic mode
altcha-lib verify challenge.json solution.json \
  --hmac-secret mysecret \
  --hmac-key-secret mykeysecret
```

---

### `obfuscate` / `deobfuscate`

Obfuscates or deobfuscates a string. The input can be provided as an argument or via stdin.

```sh
altcha-lib obfuscate [data]
altcha-lib deobfuscate [data]
```

See the [Obfuscation](./obfuscation.md) documentation for details.

---

## Full Workflow Example

```sh
# 1. Create a signed challenge and save it
altcha-lib create \
  --algorithm PBKDF2/SHA-256 \
  --cost 5000 \
  --hmac-secret mysecret \
  --expires 300 \
  > challenge.json

# 2. Solve it with 4 workers and save the solution
altcha-lib solve challenge.json --workers 4 > solution.json

# 3. Verify the solution
altcha-lib verify challenge.json solution.json --hmac-secret mysecret
```

Output of `verify` on success:

```json
{
  "expired": false,
  "invalidSignature": false,
  "invalidSolution": false,
  "time": 4.5,
  "verified": true
}
```
