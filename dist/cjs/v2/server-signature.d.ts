import { type ServerSignaturePayload, type ServerSignatureVerificationData, type VerifyServerSignatureResult } from './types.js';
export declare function parseVerificationData(data: string, convertToArray?: string[]): ServerSignatureVerificationData | null;
export declare function verifyFieldsHash(options: {
    formData: FormData | Record<string, unknown>;
    fields: string[];
    fieldsHash: string;
    algorithm?: string;
}): Promise<boolean>;
export declare function verifyServerSignature(options: {
    payload: ServerSignaturePayload;
    hmacSecret: string;
}): Promise<VerifyServerSignatureResult>;
