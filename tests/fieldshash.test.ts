import { describe, it, expect } from 'vitest';
import { verifyFieldsHash } from '../lib/index.js';
import { hashHex } from '../lib/helpers.js';
import type { Algorithm } from '../lib/types.js';

if (!('crypto' in globalThis)) {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  globalThis.crypto = require('node:crypto').webcrypto;
}

if (!('FormData' in globalThis)) {
  // Node.js 16 doesn't have FormData, mock using URLSearchParams
  // @ts-expect-error Blob type
  globalThis.FormData = URLSearchParams;
}

const formData = new FormData();
formData.append('field1', 'value1');
formData.append('field2', 'value2');
formData.append('field3', 'multi\r\nline\nvalue');

const fields = ['field1', 'field2', 'field3'];
const algorithm = 'SHA-256' as const;

async function createFieldsHash(
  fields: string[],
  formData: Record<string, unknown>,
  algorithm: Algorithm
) {
  const lines = fields.map((field) => String(formData[field] || ''));
  return await hashHex(algorithm, lines.join('\n'));
}

describe('verifyFieldsHash', () => {
  it('should verify fields hash correctly when formData is a FormData instance', async () => {
    const fieldsHash = await createFieldsHash(
      fields,
      Object.fromEntries(formData),
      algorithm
    );
    const result = await verifyFieldsHash(
      formData,
      fields,
      fieldsHash,
      algorithm
    );
    expect(result).toBe(true);
  });

  it('should fail to verify fields hash with incorrect fieldsHash', async () => {
    const result = await verifyFieldsHash(
      formData,
      fields,
      'incorrectHash',
      algorithm
    );
    expect(result).toBe(false);
  });

  it('should verify fields hash correctly when formData is a plain object', async () => {
    const plainFormData = {
      field1: 'value1',
      field2: 'value2',
    };
    const fieldsHash = await createFieldsHash(fields, plainFormData, algorithm);
    const result = await verifyFieldsHash(
      plainFormData,
      fields,
      fieldsHash,
      algorithm
    );
    expect(result).toBe(true);
  });

  it('should fail to verify fields hash with missing field in formData', async () => {
    const incompleteFormData = new FormData();
    incompleteFormData.append('field1', 'value1');
    const fieldsHash = await createFieldsHash(
      fields,
      Object.fromEntries(formData),
      algorithm
    );
    const result = await verifyFieldsHash(
      incompleteFormData,
      fields,
      fieldsHash,
      algorithm
    );
    expect(result).toBe(false);
  });

  it('should fail to verify fields hash with modified field value in formData', async () => {
    const wrongFormData = new FormData();
    wrongFormData.append('field1', formData.get('field1')!);
    wrongFormData.append('field2', 'wrong value');
    wrongFormData.append('field3', formData.get('field3')!);
    const fieldsHash = await createFieldsHash(
      fields,
      Object.fromEntries(formData),
      algorithm
    );
    const result = await verifyFieldsHash(
      wrongFormData,
      fields,
      fieldsHash,
      algorithm
    );
    expect(result).toBe(false);
  });
});
