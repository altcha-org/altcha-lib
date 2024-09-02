/**
 * Run: deno test --allow-read tests/deno.ts
 */

import { assertEquals } from 'https://deno.land/std@0.213.0/assert/mod.ts';
import {
  createChallenge,
  verifySolution,
  solveChallenge,
  solveChallengeWorkers,
  verifyFieldsHash,
  verifyServerSignature,
} from '../deno_dist/index.ts';
import { hash, hashHex, hmacHex } from '../deno_dist/helpers.ts';

const hmacKey = 'test';

Deno.test('createChallenge()', async (t) => {
  await t.step('should create a new challenge', async () => {
    const challenge = await createChallenge({
      hmacKey,
    });
    assertEquals(challenge.algorithm, 'SHA-256');
    assertEquals(challenge.salt.length, 24);
    assertEquals(challenge.challenge.length, 64);
    assertEquals(challenge.signature.length, 64);
  });
});

Deno.test('verifySolution()', async (t) => {
  await t.step('should verify solution', async () => {
    const number = 100;
    const challenge = await createChallenge({
      hmacKey,
      number,
    });
    const ok = await verifySolution(
      {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number,
        salt: challenge.salt,
        signature: challenge.signature,
      },
      hmacKey,
      false // don't check expires
    );
    assertEquals(ok, true);
  });
});

Deno.test('verifyFieldsHash()', async (t) => {
  await t.step('should fields hash', async () => {
    const fields = ['field1', 'field2', 'field3'];
    const formData = new FormData();
    formData.append('field1', 'value1');
    formData.append('field2', 'value2');
    formData.append('field3', 'multi\r\nline\nvalue');
    const lines = fields.map((field) => String(formData.get(field) || ''));
    const fieldsHash = await hashHex('SHA-256', lines.join('\n'));
    const result = await verifyFieldsHash(
      formData,
      fields,
      fieldsHash,
      'SHA-256'
    );
    assertEquals(result, true);
  });
});

Deno.test('verifyServerSignature()', async (t) => {
  await t.step('should verify server signature', async () => {
    const time = Math.floor(Date.now() / 1000);
    const verificationData = new URLSearchParams({
      email: 'test@example.net',
      expire: String(time + 10000),
      time: String(time),
      verified: String(true),
    }).toString();
    const signature = await hmacHex(
      'SHA-256',
      await hash('SHA-256', verificationData),
      hmacKey
    );
    const payload = btoa(
      JSON.stringify({
        algorithm: 'SHA-256',
        signature,
        verificationData,
        verified: true,
      })
    );
    const result = await verifyServerSignature(payload, hmacKey);
    assertEquals(result.verified, true);
  });
});

Deno.test('solveChallenge()', async (t) => {
  await t.step('should solve challenge', async () => {
    const number = 100;
    const challenge = await createChallenge({
      hmacKey,
      number,
    });
    const result = await solveChallenge(challenge.challenge, challenge.salt)
      .promise;
    assertEquals(result?.number, number);
  });
});

Deno.test('solveChallengeWorkers()', async (t) => {
  await t.step('should solve challenge', async () => {
    const number = 100;
    const challenge = await createChallenge({
      hmacKey,
      number,
    });
    const result = await solveChallengeWorkers(
      new URL('../deno_dist/worker.ts', import.meta.url),
      8,
      challenge.challenge,
      challenge.salt
    );
    assertEquals(result?.number, number);
  });
});
