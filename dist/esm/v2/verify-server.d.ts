import type { VerifyServerOptions, VerifyServerResult } from './types.js';
/** Verifies a payload remotely via the ALTCHA Sentinel `/v2/verify/signature` API. */
export declare function verifyServer(options: VerifyServerOptions): Promise<VerifyServerResult>;
