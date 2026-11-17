import { type ServerSignaturePayload, type ServerSignatureVerificationData, type VerifyServerSignatureResult } from './types.js';
export declare function parseVerificationData(data: string, convertToArray?: string[]): ServerSignatureVerificationData | null;
export declare function verifyFieldsHash(options: {
    formData: FormData | Record<string, unknown>;
    fields: string[];
    fieldsHash: string;
    algorithm?: string;
}): Promise<boolean>;
/**
 * Verifies a server-signed payload from ALTCHA Sentinel locally with the API key's secret.
 * `payload` is the base64-encoded JSON string submitted by the widget, or its decoded object.
 * An undecodable payload or one without `algorithm` returns `verified: false` with
 * `invalidSolution: true`.
 */
export declare function verifyServerSignature(options: {
    payload: string | ServerSignaturePayload;
    hmacSecret: string;
}): Promise<VerifyServerSignatureResult>;
