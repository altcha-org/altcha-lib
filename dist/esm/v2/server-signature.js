import { bufferToHex, constantTimeEqual, hash, hmac, timeDuration, } from './helpers.js';
export function parseVerificationData(data, convertToArray = ['fields', 'reasons']) {
    const verificationData = {};
    try {
        const params = new URLSearchParams(data);
        for (const [key, value] of params.entries()) {
            if (value === 'true' || value === 'false') {
                // Boolean
                verificationData[key] = value === 'true';
            }
            else if (value !== null && /^\d+?$/.test(value)) {
                // Integer
                verificationData[key] = parseInt(value, 10);
            }
            else if (value !== null && /^\d+\.\d+?$/.test(value)) {
                // Float
                verificationData[key] = parseFloat(value);
            }
            else if (value !== null) {
                // String
                verificationData[key] =
                    convertToArray.includes(key) && value.length
                        ? value.trim().split(',')
                        : value.trim();
            }
        }
    }
    catch {
        return null;
    }
    return verificationData;
}
export async function verifyFieldsHash(options) {
    const { algorithm = 'SHA-256', formData, fields, fieldsHash } = options;
    const data = formData instanceof FormData ? Object.fromEntries(formData) : formData;
    const lines = [];
    for (const field of fields) {
        lines.push(String(data[field] || ''));
    }
    return bufferToHex(await hash(algorithm, lines.join('\n'))) === fieldsHash;
}
export async function verifyServerSignature(options) {
    const { hmacSecret, payload } = options;
    const start = performance.now();
    const signature = bufferToHex(await hmac(payload.algorithm, await hash(payload.algorithm, payload.verificationData), hmacSecret));
    const verificationData = parseVerificationData(payload.verificationData);
    const expired = !!verificationData &&
        !!verificationData.expire &&
        verificationData.expire < Math.floor(Date.now() / 1000);
    const invalidSignature = !constantTimeEqual(payload.signature, signature);
    const invalidSolution = !verificationData ||
        verificationData.verified !== true ||
        payload.verified !== true;
    const verified = !expired && !invalidSignature && !invalidSolution;
    return {
        expired,
        invalidSignature,
        invalidSolution,
        time: timeDuration(start),
        verificationData,
        verified,
    };
}
