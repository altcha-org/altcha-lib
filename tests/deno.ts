import { assertEquals } from 'https://deno.land/std@0.213.0/assert/mod.ts';
import { createChallenge, verifySolution } from '../deno_dist/index.ts';

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
