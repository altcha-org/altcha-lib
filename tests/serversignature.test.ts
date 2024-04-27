import { describe, expect, it } from 'vitest';
import { verifyServerSignature } from '../lib/index.js';
import { hash, hmacHex } from '../lib/helpers.js';

describe('server signature', () => {
  const hmacKey = 'test key';

  describe('verifyServerSignature()', () => {
    it('shoult return verified', async () => {
      const time = Math.floor(Date.now() / 1000);
      const verificationData = new URLSearchParams({
        email: 'čžýěžě@sfffd.net',
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
      expect(result.verified).toEqual(true);
    });
  });
});
