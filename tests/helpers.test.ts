import { describe, expect, it } from 'vitest';
import { ab2hex, hash, hmac, randomBytes, randomInt } from '../lib/helpers.js';

const encoder = new TextEncoder();

describe('helpers', () => {
  describe('ab2hex()', () => {
    it('should return hex-encoded string', () => {
      expect(ab2hex(encoder.encode('hello world'))).toEqual(
        '68656c6c6f20776f726c64'
      );
    });
  });

  describe('hash()', () => {
    it('should return SHA-1 hash', async () => {
      expect(await hash('SHA-1', 'hello world')).toEqual(
        '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed'
      );
    });

    it('should return SHA-256 hash', async () => {
      expect(await hash('SHA-256', 'hello world')).toEqual(
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
      );
    });

    it('should return SHA-512 hash', async () => {
      expect(await hash('SHA-512', 'hello world')).toEqual(
        '309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f'
      );
    });
  });

  describe('hmac()', () => {
    it('should return HMAC-1', async () => {
      expect(await hmac('SHA-1', 'hello world', 'test')).toEqual(
        '5a09e304f3c60d633ff16735ec931e1116ff21d1'
      );
    });
    it('should return HMAC-256', async () => {
      expect(await hmac('SHA-256', 'hello world', 'test')).toEqual(
        'd1596e0d4280f2bd2d311ce0819f23bde0dc834d8254b92924088de94c38d922'
      );
    });
    it('should return HMAC-512', async () => {
      expect(await hmac('SHA-512', 'hello world', 'test')).toEqual(
        '2536d175df94a4638110701d8a0e2cbe56e35f2dcfd167819148cd0f2c8780cb3d3df52b4aea8f929004dd07235ae802f4b5d160a2b8b82e8c2f066289de85a3'
      );
    });
  });

  describe('randomBytes()', () => {
    it('should return an Uint8Array with random values', () => {
      const ab = randomBytes(10);
      expect(ab.length).toEqual(10);
      expect([...ab].some((b) => b !== 0)).toBeTruthy();
    });
  });

  describe('randomInt()', () => {
    it('should return a random integers', () => {
      const max = 1000;
      const numbers = [
        randomInt(max),
        randomInt(max),
        randomInt(max),
        randomInt(max),
        randomInt(max),
        randomInt(max),
      ];
      expect(numbers.some((n) => n !== numbers[0]));
    });

    it('should return a random integer within the limit', () => {
      const max = 4;
      for (let i = 1; i < 1000; i++) {
        const num = randomInt(max);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThanOrEqual(max);
      }
    });
  });
});
