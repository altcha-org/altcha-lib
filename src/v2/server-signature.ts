import {
	assertAlgorithm,
	assertSecret,
	bufferToHex,
	constantTimeEqual,
	hash,
	hmac,
	timeDuration,
} from './helpers.js';
import {
	HmacAlgorithm,
	type ServerSignaturePayload,
	type ServerSignatureVerificationData,
	type VerifyServerSignatureResult,
} from './types.js';

/**
 * Algorithms accepted for server signatures and fields hashes.
 * SHA-1 is kept because Sentinel signs v1 challenges with the challenge's own algorithm.
 */
const SERVER_SIGNATURE_ALGORITHMS = ['SHA-1', ...Object.values(HmacAlgorithm)];

export function parseVerificationData(
	data: string,
	convertToArray: string[] = ['fields', 'reasons']
) {
	const verificationData: ServerSignatureVerificationData = {};
	try {
		const params = new URLSearchParams(data);
		for (const [key, value] of params.entries()) {
			if (value === 'true' || value === 'false') {
				// Boolean
				verificationData[key] = value === 'true';
			} else if (value !== null && /^\d+?$/.test(value)) {
				// Integer
				verificationData[key] = parseInt(value, 10);
			} else if (value !== null && /^\d+\.\d+?$/.test(value)) {
				// Float
				verificationData[key] = parseFloat(value);
			} else if (value !== null) {
				// String
				verificationData[key] =
					convertToArray.includes(key) && value.length
						? value.trim().split(',')
						: value.trim();
			}
		}
	} catch {
		return null;
	}
	return verificationData;
}

export async function verifyFieldsHash(options: {
	formData: FormData | Record<string, unknown>;
	fields: string[];
	fieldsHash: string;
	algorithm?: string;
}): Promise<boolean> {
	const { algorithm = 'SHA-256', formData, fields, fieldsHash } = options;
	assertAlgorithm(algorithm, SERVER_SIGNATURE_ALGORITHMS);
	const data: Record<string, unknown> =
		formData instanceof FormData ? Object.fromEntries(formData) : formData;
	const lines = [];
	for (const field of fields) {
		lines.push(String(data[field] || ''));
	}
	return bufferToHex(await hash(algorithm, lines.join('\n'))) === fieldsHash;
}

export async function verifyServerSignature(options: {
	payload: ServerSignaturePayload;
	hmacSecret: string;
}): Promise<VerifyServerSignatureResult> {
	const { hmacSecret, payload } = options;
	// `algorithm` is not covered by the signature, so it must be validated before use.
	assertAlgorithm(payload.algorithm, SERVER_SIGNATURE_ALGORITHMS);
	assertSecret('hmacSecret', hmacSecret);
	const start = performance.now();
	const signature = bufferToHex(
		await hmac(
			payload.algorithm as HmacAlgorithm,
			await hash(payload.algorithm, payload.verificationData),
			hmacSecret
		)
	);
	const verificationData = parseVerificationData(payload.verificationData);
	// Same comparison as `verifySolution`: expired as soon as the current (fractional)
	// second passes `expire`. A missing or empty `expire` means the payload does not expire.
	const expired =
		!!verificationData &&
		!!verificationData.expire &&
		verificationData.expire < Date.now() / 1000;
	const invalidSignature =
		typeof payload.signature !== 'string' ||
		!constantTimeEqual(payload.signature, signature);
	const invalidSolution =
		!verificationData ||
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
