# Using the `/verify` Route

Framework plugins include a `/verify` endpoint that can be used internally or by external services to verify ALTCHA payloads.

## Usage

Send the Base64-encoded payload returned by the ALTCHA widget as the `altcha` field. This value is typically obtained from a form field or a cookie.

```ts
const resp = await fetch('http://localhost:3000/altcha/verify', {
  body: JSON.stringify({
    altcha: '...', // Base64-encoded ALTCHA payload
  }),
  headers: {
    'content-type': 'application/json',
  },
  method: 'POST',
});

const result = resp.status === 200 ? await resp.json() : null;

if (result?.verification?.verified === true) {
  // Success
}
```

**Note:** The field name `altcha` can be changed using the `fieldName` option in the `create()` configuration.

**Note:** This route always verifies locally, even if `verifyServer` is configured — it never
calls out to Sentinel. It's meant for external/custom integrations that trust your server's
own `hmacSignatureSecret`-based check. If a custom integration needs remote Sentinel
verification, call the exported `verifyServer()` function directly. See
[`/docs/server-signatures.md`](/docs/server-signatures.md#remote-verification-sentinel-api).

## Verification Result

```ts
interface AltchaResult {
  error: string | null;
  payload: Payload | ServerSignaturePayload | null;
  verification: VerifySolutionResult | null;
}

interface VerifySolutionResult {
  expired: boolean;
  invalidSignature: boolean | null;
  invalidSolution: boolean | null;
  time: number;
  verified: boolean;
}
```
