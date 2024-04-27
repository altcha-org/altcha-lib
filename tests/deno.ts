/**
 * Run: deno test --allow-read tests/deno.ts
 */

import { assertEquals } from 'https://deno.land/std@0.213.0/assert/mod.ts';
import {
  createChallenge,
  verifySolution,
  solveChallenge,
  solveChallengeWorkers,
} from '../deno_dist/index.ts';

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
      hmacKey
    );
    assertEquals(ok, true);
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
