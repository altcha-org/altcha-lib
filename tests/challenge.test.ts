import { describe, expect, it } from 'vitest';
import { createChallenge, verifySolution } from '../lib/index.js';
import { Challenge } from '../lib/types.js';

describe('challenge', () => {
  const hmacKey = 'test key';

  describe('createChallenge()', () => {
    it('should return a new challenge object with default algorithm', async () => {
      const challenge = await createChallenge({
        hmacKey,
      });
      expect(challenge).toEqual({
        algorithm: 'SHA-256',
        challenge: expect.any(String),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toEqual(24);
      expect(challenge.challenge.length).toEqual(64);
      expect(challenge.signature.length).toEqual(64);
    });

    it('should return a new challenge object with SHA-1', async () => {
      const challenge = await createChallenge({
        algorithm: 'SHA-1',
        hmacKey,
      });
      expect(challenge).toEqual({
        algorithm: 'SHA-1',
        challenge: expect.any(String),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toEqual(24);
      expect(challenge.challenge.length).toEqual(40);
      expect(challenge.signature.length).toEqual(40);
    });

    it('should return a new challenge object with SHA-512', async () => {
      const challenge = await createChallenge({
        algorithm: 'SHA-512',
        hmacKey,
      });
      expect(challenge).toEqual({
        algorithm: 'SHA-512',
        challenge: expect.any(String),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toEqual(24);
      expect(challenge.challenge.length).toEqual(128);
      expect(challenge.signature.length).toEqual(128);
    });
  });

  describe('verifySolution()', () => {
    it('should return true', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
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
      expect(ok).toEqual(true);
    });

    it('should return false if number is incorrect', async () => {
      const challenge = await createChallenge({
        number: 100,
        hmacKey,
      });
      const ok = await verifySolution(
        {
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number: 444,
          salt: challenge.salt,
          signature: challenge.signature,
        },
        hmacKey
      );
      expect(ok).toEqual(false);
    });

    it('should return false if salt is incorrect', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const ok = await verifySolution(
        {
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number,
          salt: 'wrong salt',
          signature: challenge.signature,
        },
        hmacKey
      );
      expect(ok).toEqual(false);
    });

    it('should return false if signature is incorrect', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const ok = await verifySolution(
        {
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number,
          salt: challenge.salt,
          signature: 'wrong signature',
        },
        hmacKey
      );
      expect(ok).toEqual(false);
    });

    it('should return false if hmacKey is incorrect', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const ok = await verifySolution(
        {
          algorithm: challenge.algorithm,
          challenge: challenge.challenge,
          number,
          salt: challenge.salt,
          signature: challenge.signature,
        },
        'wrong key'
      );
      expect(ok).toEqual(false);
    });

    it('should return false if algorithm is incorrect', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const ok = await verifySolution(
        {
          algorithm: 'SHA-1',
          challenge: challenge.challenge,
          number,
          salt: challenge.salt,
          signature: challenge.signature,
        },
        hmacKey
      );
      expect(ok).toEqual(false);
    });
  });
});
