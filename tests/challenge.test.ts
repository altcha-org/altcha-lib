import { describe, expect, it } from 'vitest';
import {
  createChallenge,
  extractParams,
  solveChallenge,
  solveChallengeWorkers,
  verifySolution,
} from '../lib/index.js';
import { Challenge } from '../lib/types.js';

if (!('crypto' in globalThis)) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  globalThis.crypto = require('node:crypto').webcrypto;
}

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
        maxnumber: expect.any(Number),
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
        maxnumber: expect.any(Number),
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
        maxnumber: expect.any(Number),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toEqual(24);
      expect(challenge.challenge.length).toEqual(128);
      expect(challenge.signature.length).toEqual(128);
    });

    it('should return a new challenge with expires param', async () => {
      const expires = new Date(Date.now() + 3600000);
      const challenge = await createChallenge({
        algorithm: 'SHA-256',
        expires,
        hmacKey,
      });
      expect(challenge).toEqual({
        algorithm: 'SHA-256',
        challenge: expect.any(String),
        maxnumber: expect.any(Number),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toBeGreaterThan(24);
      expect(challenge.salt.includes('?expires=')).toBeTruthy();
      expect(challenge.challenge.length).toEqual(64);
      expect(challenge.signature.length).toEqual(64);
    });

    it('should return a new challenge with custom params', async () => {
      const challenge = await createChallenge({
        algorithm: 'SHA-256',
        hmacKey,
        params: {
          abc: '123',
          xyz: '000'
        },
      });
      expect(challenge).toEqual({
        algorithm: 'SHA-256',
        challenge: expect.any(String),
        maxnumber: expect.any(Number),
        salt: expect.any(String),
        signature: expect.any(String),
      } satisfies Challenge);
      expect(challenge.salt.length).toBeGreaterThan(24);
      expect(challenge.salt.endsWith('?abc=123&xyz=000')).toBeTruthy();
      expect(challenge.challenge.length).toEqual(64);
      expect(challenge.signature.length).toEqual(64);
    });
  });

  describe('extractParams', () => {
    it('should extract custom params from payload', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
        params: {
          abc: '123',
          xyz: '000'
        },
      });
      const params = extractParams({
        ...challenge,
        number,
      });
      expect(params).toEqual({
        abc: '123',
        xyz: '000'
      });
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

    it('should return true with expires in the future', async () => {
      const number = 100;
      const challenge = await createChallenge({
        expires: new Date(Date.now() + 3600000),
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

    it('should return false if the challenge expired', async () => {
      const number = 100;
      const challenge = await createChallenge({
        expires: new Date(Date.now() - 3600000),
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
      expect(ok).toEqual(false);
    });
  });

  describe('solveChallenge', () => {
    it('should solve challenge', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const { promise } = solveChallenge(
        challenge.challenge,
        challenge.salt,
        challenge.algorithm
      );
      const result = await promise;
      expect(result?.number).toEqual(number);
    });
  });

  describe.skipIf(!('Worker' in globalThis))('solveChallengeWorkers', () => {
    it('should solve challenge using workers', async () => {
      const number = 100;
      const challenge = await createChallenge({
        number,
        hmacKey,
      });
      const result = await solveChallengeWorkers(
        () =>
          new Worker('./lib/worker.ts', {
            type: 'module',
          }),
        4,
        challenge.challenge,
        challenge.salt,
        challenge.algorithm
      );
      expect(result?.number).toEqual(number);
    });
  });
});
